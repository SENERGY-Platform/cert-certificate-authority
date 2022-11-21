package main

import (
	"ca/config"
	"ca/db"
	"ca/server"
	"log"

	cfssl_log "github.com/cloudflare/cfssl/log"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Printf("[ERROR] can not read config: %s", err)
		return
	}
	cfssl_log.Level = cfssl_log.LevelDebug
	dbConnection, err := db.GetDB(config)
	if err != nil {
		cfssl_log.Errorf("can not connect to DB: %s", err)
		return
	}
	server.StartServer(dbConnection, config)

}
