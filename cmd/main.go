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
	"fmt"
	"log"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/notifier"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/server"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/db"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
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
	dbConnection, err := db.GetDB(config)
	if err != nil {
		config.GetLogger().Error(fmt.Sprintf("can not connect to DB: %s", err))
		return
	}
	ctx := context.Background()
	err = notifier.StartNotifier(ctx, dbConnection, config)
	if err != nil {
		config.GetLogger().Error(fmt.Sprintf("[ERROR] can not start notifier: %s", err))
		return
	}
	server.StartServer(ctx, dbConnection, config)

}
