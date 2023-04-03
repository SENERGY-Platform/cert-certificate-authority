package main

import (
	"log"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/server"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/db"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"

	cfssl_log "github.com/cloudflare/cfssl/log"
)

// @title Certificate Authority
// @version 1.0
// @description This is a private certificate authority that builds on top of CFSSL
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
