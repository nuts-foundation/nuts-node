/*
 * Copyright (C) 2023 Nuts community
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
 *
 */

package discoveryservice

//
//import (
//	"encoding/json"
//	"errors"
//	"fmt"
//	"github.com/google/uuid"
//	"github.com/nuts-foundation/go-did/vc"
//	"github.com/nuts-foundation/nuts-node/discoveryservice/log"
//	"gorm.io/gorm"
//	"gorm.io/gorm/clause"
//	"io"
//	"net/http"
//	"net/url"
//	"strconv"
//	"strings"
//	"sync"
//	"time"
//)
//
//func newClient(db *gorm.DB, definitions map[string]Definition) (*client, error) {
//	result := &client{
//		db:          db,
//		definitions: definitions,
//	}
//	if err := initializeSQLStore(db, definitions); err != nil {
//		return nil, err
//	}
//	return result, nil
//}
//
//type client struct {
//	db          *gorm.DB
//	definitions map[string]Definition
//}
//
//func (c *client) Search(serviceID string, query map[string]string) ([]vc.VerifiablePresentation, error) {
//	propertyColumns := map[string]string{
//		"id":                   "cred.credential_id",
//		"issuer":               "cred.credential_issuer",
//		"type":                 "cred.credential_type",
//		"credentialSubject.id": "cred.credential_subject_id",
//	}
//
//	stmt := c.db.Model(&entry{}).
//		Where("usecase_id = ?", serviceID).
//		Joins("inner join usecase_client_credential cred ON cred.entry_id = usecase_client_entries.id")
//	numProps := 0
//	for jsonPath, value := range query {
//		if value == "*" {
//			continue
//		}
//		// sort out wildcard mode
//		var eq = "="
//		if strings.HasPrefix(value, "*") {
//			value = "%" + value[1:]
//			eq = "LIKE"
//		}
//		if strings.HasSuffix(value, "*") {
//			value = value[:len(value)-1] + "%"
//			eq = "LIKE"
//		}
//		if column := propertyColumns[jsonPath]; column != "" {
//			stmt = stmt.Where(column+" "+eq+" ?", value)
//		} else {
//			// This property is not present as column, but indexed as key-value property.
//			// Multiple (inner) joins to filter on a dynamic number of properties to filter on is not pretty, but it works
//			alias := "p" + strconv.Itoa(numProps)
//			numProps++
//			stmt = stmt.Joins("inner join usecase_client_credential_props "+alias+" ON "+alias+".id = cred.id AND "+alias+".key = ? AND "+alias+".value "+eq+" ?", jsonPath, value)
//		}
//	}
//
//	var matches []entry
//	if err := stmt.Find(&matches).Error; err != nil {
//		return nil, err
//	}
//	var results []vc.VerifiablePresentation
//	for _, match := range matches {
//		if match.PresentationExpiration <= time.Now().Unix() {
//			continue
//		}
//		presentation, err := vc.ParseVerifiablePresentation(match.PresentationRaw)
//		if err != nil {
//			return nil, fmt.Errorf("failed to parse presentation '%s': %w", match.PresentationID, err)
//		}
//		results = append(results, *presentation)
//	}
//	return results, nil
//}
//
//func (c *client) refreshAll() {
//	wg := &sync.WaitGroup{}
//	for _, definition := range c.definitions {
//		wg.Add(1)
//		go func(definition Definition) {
//			c.refreshList(definition)
//		}(definition)
//	}
//	wg.Done()
//}
//
//func (c *client) refreshList(definition Definition) error {
//	var currentService discoveryService
//	if err := c.db.Find(&currentService, "usecase_id = ?", definition.ID).Error; errors.Is(err, gorm.ErrRecordNotFound) {
//		// First refresh of the list
//		if err := c.db.Create(&discoveryService{ID: definition.ID}).Error; err != nil {
//			return err
//		}
//	} else if err != nil {
//		// Other error
//		return err
//	}
//	log.Logger().Debugf("Refreshing use case list %s", definition.ID)
//	// replace with generated client later
//	requestURL, _ := url.Parse(definition.Endpoint)
//	requestURL.Query().Add("timestamp", fmt.Sprintf("%d", currentService.Timestamp))
//	httpResponse, err := http.Get(definition.Endpoint)
//	if err != nil {
//		return err
//	}
//	data, err := io.ReadAll(httpResponse.Body)
//	if err != nil {
//		return err
//	}
//	var response ListResponse
//	if err = json.Unmarshal(data, &response); err != nil {
//		return err
//	}
//	return c.applyDelta(currentService.UsecaseID, response.Entries, response.Tombstone, currentService.Timestamp, response.Timestamp)
//}
//
//// applyDelta applies the updateTimestamp, retrieved from the use case list server, to the local index of the use case lists.
//func (c *client) applyDelta(usecaseID string, presentations []vc.VerifiablePresentation, tombstoneSet []string, previousTimestamp uint64, timestamp uint64) error {
//	// TODO: validate presentations
//	if previousTimestamp == timestamp {
//		// nothing to do
//		return nil
//	}
//	// We use a transaction to make sure the complete updateTimestamp is applied, or nothing at all.
//	// Use a lock on the list to make sure there are no concurrent updates being applied to the list,
//	// which could lead to the client becoming out-of-sync with the server list.
//	// This situation can only really occur in a distributed system (multiple nodes updating the same list at the same time, with a different timestamp),
//	// or bug in the updateTimestamp scheduler.
//	return c.db.Transaction(func(tx *gorm.DB) error {
//		// Lock the list, check if we're applying the delta to the right starting point
//		var currentList list
//		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
//			Where("usecase_id = ?", usecaseID).
//			Find(&currentList).
//			Error; err != nil {
//			return err
//		}
//		// Make sure we don't apply stale data
//		if currentList.Timestamp != previousTimestamp {
//			log.Logger().Infof("Not applying delta to use case list '%s': timestamp mismatch (expected %d but was %d). "+
//				"Probably caused by multiple processes updating the list. This is not a problem/bug: stale data should be updated at next refresh.", usecaseID, previousTimestamp, currentList.Timestamp)
//			return nil
//		}
//		// Now we can apply the delta:
//		// - delete removed presentations
//		// - add new presentations
//		// - index the presentations' properties
//		if len(tombstoneSet) > 0 {
//			if err := tx.Delete(&entry{}, "usecase_id = ? AND presentation_id IN ?", usecaseID, tombstoneSet).Error; err != nil {
//				return fmt.Errorf("failed to delete tombstone records: %w", err)
//			}
//		}
//		for _, presentation := range presentations {
//			err := c.writePresentation(tx, usecaseID, presentation)
//			if err != nil {
//				return err
//			}
//		}
//		// Finally, updateTimestamp the list timestamp
//		if err := tx.Model(&list{}).Where("usecase_id = ?", usecaseID).Update("timestamp", timestamp).Error; err != nil {
//			return fmt.Errorf("failed to updateTimestamp timestamp: %w", err)
//		}
//		return nil
//	})
//}
//
//func (c *client) writePresentation(tx *gorm.DB, usecaseID string, presentation vc.VerifiablePresentation) error {
//	entryID := uuid.NewString()
//	// Store list entry / verifiable presentation
//	newEntry := entry{
//		ID:                     entryID,
//		UsecaseID:              usecaseID,
//		PresentationID:         presentation.ID.String(),
//		PresentationRaw:        presentation.Raw(),
//		PresentationExpiration: presentation.JWT().Expiration().Unix(),
//	}
//	// Store the credentials of the presentation
//	for _, curr := range presentation.VerifiableCredential {
//		var credentialType *string
//		for _, currType := range curr.Type {
//			if currType.String() != "VerifiableCredential" {
//				credentialType = new(string)
//				*credentialType = currType.String()
//				break
//			}
//		}
//		subjectDID, err := curr.SubjectDID()
//		if err != nil {
//			return fmt.Errorf("invalid credential subject ID for VP '%s': %w", presentation.ID, err)
//		}
//		credentialRecordID := uuid.NewString()
//		cred := credential{
//			ID:                  credentialRecordID,
//			EntryID:             entryID,
//			CredentialID:        curr.ID.String(),
//			CredentialIssuer:    curr.Issuer.String(),
//			CredentialSubjectID: subjectDID.String(),
//			CredentialType:      credentialType,
//		}
//		if len(curr.CredentialSubject) != 1 {
//			return errors.New("credential must contain exactly one subject")
//		}
//		// Store credential properties
//		keys, values := indexJSONObject(curr.CredentialSubject[0].(map[string]interface{}), nil, nil, "credentialSubject")
//		for i, key := range keys {
//			if key == "credentialSubject.id" {
//				// present as column, don't index
//				continue
//			}
//			cred.Properties = append(cred.Properties, credentialProperty{
//				ID:    credentialRecordID,
//				Key:   key,
//				Value: values[i],
//			})
//		}
//		newEntry.Credentials = append(newEntry.Credentials, cred)
//	}
//	if err := tx.Create(&newEntry).Error; err != nil {
//		return fmt.Errorf("failed to create entry: %w", err)
//	}
//	return nil
//}
//
//// indexJSONObject indexes a JSON object, resulting in a slice of JSON paths and corresponding string values.
//// It only traverses JSON objects and only adds string values to the result.
//func indexJSONObject(target map[string]interface{}, jsonPaths []string, stringValues []string, currentPath string) ([]string, []string) {
//	for key, value := range target {
//		thisPath := currentPath
//		if len(thisPath) > 0 {
//			thisPath += "."
//		}
//		thisPath += key
//
//		switch typedValue := value.(type) {
//		case string:
//			jsonPaths = append(jsonPaths, thisPath)
//			stringValues = append(stringValues, typedValue)
//		case map[string]interface{}:
//			jsonPaths, stringValues = indexJSONObject(typedValue, jsonPaths, stringValues, thisPath)
//		default:
//			// other values (arrays, booleans, numbers, null) are not indexed
//		}
//	}
//	return jsonPaths, stringValues
//}
