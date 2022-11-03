package main

import (
	"ca/db"
	"ca/server"
)

func main() {
	dbConnection, err := db.GetDB()
	if err != nil {
		server.StartServer(dbConnection)
	}
}
