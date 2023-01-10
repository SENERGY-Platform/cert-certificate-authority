package main

import (
	"ca/internal/config"
	"ca/internal/db"
	"ca/internal/server"
	"log"

	cfssl_log "github.com/cloudflare/cfssl/log"
)

// @title Certificate Authority
// @version 1.0
// @description This is a private certificate authority that builds on top of CFSSL

// @host petstore.swagger.io
// @BasePath /v2
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
