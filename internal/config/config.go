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

package config

import (
	"os"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/log"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort       int
	DBDriver         string
	DBUser           string
	DBDatabase       string
	DBPassword       string
	DBAddr           string
	Debug            int
	CACrtPath        string
	PrivateKeyPath   string
	OCSPCycle        time.Duration
	SignbackDuration time.Duration
	RevokeWehbook    string
}

func getStringEnv(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		i, err := strconv.Atoi(value)
		if err == nil {
			return i
		}
	}
	return fallback
}

func LoadConfig() (config Config, err error) {
	if _, fileErr := os.Stat(".env"); fileErr == nil {
		err = godotenv.Load()
		if err != nil {
			log.Errorf("cant load .env file: %s", err)
			return
		}
	}
	ocspCycle, err := time.ParseDuration(getStringEnv("OCSP_CYCLE", "24h"))
	if err != nil {
		log.Errorf("cant parse OCSP_CYCLE: %s", err)
		return
	}

	signbackDuration, err := time.ParseDuration(getStringEnv("SIGNBACK_DURATION", "5m"))
	if err != nil {
		log.Errorf("cant parse SIGNBACK_DURATION: %s", err)
		return
	}

	config = Config{
		DBDriver:         getStringEnv("DB_DRIVER", "postgres"),
		DBUser:           getStringEnv("DB_USERNAME", "user"),
		DBPassword:       getStringEnv("DB_PASSWORD", "password"),
		DBAddr:           getStringEnv("DB_ADDR", "db"),
		DBDatabase:       getStringEnv("DB_DATABASE", "db"),
		Debug:            getIntEnv("DEBUG", 0),
		ServerPort:       getIntEnv("SERVER_PORT", 8080),
		CACrtPath:        getStringEnv("CA_CERT_PATH", "/etc/certs/ca.crt"),
		PrivateKeyPath:   getStringEnv("PRIVATE_KEY_PATH", "/etc/certs/key.key"),
		RevokeWehbook:    getStringEnv("REVOKE_WEBHOOK", ""),
		OCSPCycle:        ocspCycle,
		SignbackDuration: signbackDuration,
	}

	log.Infof("Configuration: %+v\n", config)

	return
}
