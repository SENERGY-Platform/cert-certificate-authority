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
