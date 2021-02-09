/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package contract

import (
	"fmt"
	"regexp"
	"time"

	"github.com/goodsign/monday"
)

// Contract contains the contract template, the raw contract text and the extracted params.
type Contract struct {
	RawContractText string
	Template        *Template
	Params          map[string]string
}

// ParseContractString parses a raw string, finds the contract from the store and extracts the params
// Note: It does not verify the params
func ParseContractString(rawContractText string, contractTemplates TemplateStore) (*Contract, error) {

	// first, find the contract Template
	template, err := contractTemplates.FindFromRawContractText(rawContractText)
	if err != nil {
		return nil, err
	}

	contract := &Contract{
		Template:        template,
		RawContractText: rawContractText,
	}

	if err = contract.initParams(); err != nil {
		return nil, err
	}

	return contract, nil
}

func (sc *Contract) initParams() error {
	// extract the params
	r, _ := regexp.Compile(sc.Template.Regexp)
	matchResult := r.FindSubmatch([]byte(sc.RawContractText))
	if len(matchResult) < 1 {
		return fmt.Errorf("%w: could not match the contract template regex", ErrInvalidContractText)
	}
	matches := matchResult[1:]

	if len(matches) != len(sc.Template.TemplateAttributes) {
		return fmt.Errorf("%w: amount of template attributes does not match the amount of Params: found: %d, expected %d", ErrInvalidContractText, len(matches), len(sc.Template.TemplateAttributes))
	}

	sc.Params = make(map[string]string, len(matches))
	for idx, match := range matches {
		sc.Params[sc.Template.TemplateAttributes[idx]] = string(match)
	}
	return nil
}

// ErrInvalidPeriod is returned when the given period is invalid
var ErrInvalidPeriod = fmt.Errorf("%w: invalid period", ErrInvalidContractText)

// VerifyForGivenTime checks if the contract is valid for the given moment in time
func (sc Contract) VerifyForGivenTime(checkTime time.Time) error {
	var (
		err                      error
		ok                       bool
		validFrom, validTo       *time.Time
		validFromStr, validToStr string
	)

	if validFromStr, ok = sc.Params[ValidFromAttr]; !ok {
		return fmt.Errorf("%w: value for [%s] is missing", ErrInvalidContractText, ValidFromAttr)
	}

	validFrom, err = parseTime(validFromStr, sc.Template.Language)
	if err != nil {
		return fmt.Errorf("%w: unable to parse [%s]: %s", ErrInvalidContractText, ValidFromAttr, err)

	}

	if validToStr, ok = sc.Params[ValidToAttr]; !ok {
		return fmt.Errorf("%w: value for [%s] is missing", ErrInvalidContractText, ValidToAttr)
	}

	validTo, err = parseTime(validToStr, sc.Template.Language)
	if err != nil {
		return fmt.Errorf("%w: unable to parse [%s]: %s", ErrInvalidContractText, ValidToAttr, err)
	}

	// All parsed, check time range
	if validFrom.After(*validTo) {
		return fmt.Errorf("%w: [%s] must become before [%s]", ErrInvalidPeriod, ValidFromAttr, ValidToAttr)
	}

	amsterdamLocation, _ := time.LoadLocation(AmsterdamTimeZone)
	if checkTime.In(amsterdamLocation).Before(*validFrom) {
		return fmt.Errorf("%w: contract is not yet valid", ErrInvalidPeriod)
	}
	if checkTime.In(amsterdamLocation).After(*validTo) {
		return fmt.Errorf("%w: contract is expired", ErrInvalidPeriod)
	}

	return nil
}

// Verify verifies the params with the template
func (sc Contract) Verify() error {
	now := NowFunc()
	return sc.VerifyForGivenTime(now)
}

// parseTime parses the given timeStr in context of the Europe/Amsterdam time zone and uses the given language.
// Note that currently only the language "NL" is supported.
func parseTime(timeStr string, _ Language) (*time.Time, error) {
	contractIssuerTimezone, _ := time.LoadLocation(AmsterdamTimeZone)
	// TODO: add support for other languages
	parsedTime, err := monday.ParseInLocation(timeLayout, timeStr, contractIssuerTimezone, monday.LocaleNlNL)
	if err != nil {
		return nil, fmt.Errorf("invalid time string [%v]: %w", timeStr, err)
	}
	return &parsedTime, nil
}

// AmsterdamTimeZone contains the timezone of the Cannabis capital of Europe.
const AmsterdamTimeZone = "Europe/Amsterdam"
