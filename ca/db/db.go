package db

import (
	"os"

	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func GetDB() (db *sqlx.DB, err error) {
	dbConfig := dbconf.DBConfig{
		DriverName:     os.Getenv("DB_DRIVER"),
		DataSourceName: os.Getenv("DB_URL"),
	}
	return sqlx.Open(dbConfig.DriverName, dbConfig.DataSourceName)
}
