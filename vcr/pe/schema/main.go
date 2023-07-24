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

package main

import (
	"fmt"
	"github.com/a-h/generate"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	claimFormatDescriptorLocation  = "http://identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json"
	presentationDefinitionLocation = "https://github.com/decentralized-identity/presentation-exchange/raw/main/schemas/v2.0.0/presentation-definition.json"
	//presentationSubmissionLocation = "https://github.com/decentralized-identity/presentation-exchange/raw/main/schemas/v2.0.0/presentation-submission.json"
)

func main() {
	schemas := []*generate.Schema{parseSchema(claimFormatDescriptorLocation), parseSchema(presentationDefinitionLocation)}

	g := generate.New(schemas...)

	err := g.CreateTypes()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failure generating structs: ", err)
		os.Exit(1)
	}

	f, err := os.OpenFile("../generated.go", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening output file: ", err)
		return
	}

	generate.Output(f, g, "pe")
}

func parseSchema(schemaLocation string) *generate.Schema {
	//download claim format descriptor schema
	body, err := downloadSchema(schemaLocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	schema, err := generate.Parse(string(body), mustParse(schemaLocation))
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	return schema
}

func downloadSchema(schemaLocation string) ([]byte, error) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(schemaLocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "expected 200 response, got %v", resp.StatusCode)
		os.Exit(1)
	}

	// read body
	return io.ReadAll(resp.Body)
}

func mustParse(rawURL string) *url.URL {
	pURL, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return pURL
}
