package main

import (
	"ca/config"
	"ca/db"
	"ca/server"
	"log"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Printf("ERROR: can not read config: %s", err)
		return
	}

	dbConnection, err := db.GetDB(config)
	if err != nil {
		log.Printf("ERROR: can not connect to DB: %s", err)
		return
	}
	server.StartServer(dbConnection, config)

}
