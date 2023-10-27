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

package usecase

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"os"
)

type maintainerStore interface {
	ListWriter
}

type maintainerFileStore struct {
	fileName string
}

func newFileMaintainerStore(fileName string) (*maintainerFileStore, error) {
	info, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		if err = os.WriteFile(fileName, []byte("{}"), 0644); err != nil {
			return nil, fmt.Errorf("file create '%s': %w", fileName, err)
		}
	}
	if err != nil || info.IsDir() {
		return nil, fmt.Errorf("file stat '%s': %w", fileName, err)
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("data file read '%s': %w", fileName, err)
	}
	lists := make(map[string][]vc.VerifiablePresentation)
	if err = json.Unmarshal(data, &lists); err != nil {
		return nil, fmt.Errorf("data file parse '%s': %w", fileName, err)
	}
	return &maintainerFileStore{fileName: fileName}, nil
}
