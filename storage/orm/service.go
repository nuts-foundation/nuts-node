/*
 * Copyright (C) 2024 Nuts community
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

package orm

import "gorm.io/gorm/schema"

var _ schema.Tabler = (*Service)(nil)

// Service is the gorm representation of the did_service table
type Service struct {
	ID   string `gorm:"primaryKey"`
	Data []byte
}

func (v Service) TableName() string {
	return "did_service"
}
