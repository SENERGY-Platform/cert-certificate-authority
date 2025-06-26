/*
 * Copyright 2025 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package db

import (
	"fmt"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"

	"github.com/DATA-DOG/go-sqlmock"
	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func GetDB(configuration config.Config) (db *sqlx.DB, err error) {
	DriverName := configuration.DBDriver
	USER := configuration.DBUser
	DATABASE := configuration.DBDatabase
	PASSWORD := configuration.DBPassword
	ADDR := configuration.DBAddr
	DB_URL := fmt.Sprintf("%s://%s:%s@%s/%s?sslmode=disable", DriverName, USER, PASSWORD, ADDR, DATABASE)

	return sqlx.Open(DriverName, DB_URL)
}

func GetMockDB(confi config.Config) (acc *certsql.Accessor, err error) {
	db, _, err := sqlmock.New()
	if err != nil {
		return
	}
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	acc = certsql.NewAccessor(sqlxDB)
	return
}
