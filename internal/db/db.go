package db

import (
	"ca/internal/config"
	"fmt"

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
