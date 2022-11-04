package main

import (
	"ca/db"
	"ca/server"
	"log"
)

func main() {
	dbConnection, err := db.GetDB()
	if err != nil {
		log.Printf("ERROR: can not connect to DB: %s", err)
		return
	}
	server.StartServer(dbConnection)

}
