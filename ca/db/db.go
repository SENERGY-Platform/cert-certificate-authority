package db

import (
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func GetDB() (db *sqlx.DB, err error) {
	DriverName := os.Getenv("DB_DRIVER")
	USER := os.Getenv("DB_USERNAME")
	DATABASE := os.Getenv("DB_DATABASE")
	PASSWORD := os.Getenv("DB_PASSWORD")
	ADDR := os.Getenv("DB_ADDR")
	DB_URL := fmt.Sprintf("%s://%s:%s@%s/%s?sslmode=disable", DriverName, USER, PASSWORD, ADDR, DATABASE)

	return sqlx.Open(DriverName, DB_URL)
}
