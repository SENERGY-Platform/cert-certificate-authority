/*
 * Copyright 2025 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
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
	server.StartServer(context.Background(), dbConnection, config)

}
