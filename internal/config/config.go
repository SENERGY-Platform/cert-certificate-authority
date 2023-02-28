package config

import (
	"os"
	"strconv"

	"github.com/cloudflare/cfssl/log"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort     int
	DBDriver       string
	DBUser         string
	DBDatabase     string
	DBPassword     string
	DBAddr         string
	Debug          int
	CACrtPath      string
	PrivateKeyPath string
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

	config = Config{
		DBDriver:       getStringEnv("DB_DRIVER", "postgres"),
		DBUser:         getStringEnv("DB_USERNAME", "user"),
		DBPassword:     getStringEnv("DB_PASSWORD", "password"),
		DBAddr:         getStringEnv("DB_ADDR", "db"),
		DBDatabase:     getStringEnv("DB_DATABASE", "db"),
		Debug:          getIntEnv("DEBUG", 0),
		ServerPort:     getIntEnv("SERVER_PORT", 8080),
		CACrtPath:      getStringEnv("CA_CERT_PATH", "/etc/certs/ca.crt"),
		PrivateKeyPath: getStringEnv("PRIVATE_KEY_PATH", "/etc/certs/key.key"),
	}

	log.Infof("Configuration: %+v\n", config)

	return
}

func GetTestConfig() (config Config) {
	config = Config{
		DBDriver:       getStringEnv("DB_DRIVER", "postgres"),
		DBUser:         getStringEnv("DB_USERNAME", "user"),
		DBPassword:     getStringEnv("DB_PASSWORD", "password"),
		DBAddr:         getStringEnv("DB_ADDR", "db"),
		DBDatabase:     getStringEnv("DB_DATABASE", "db"),
		Debug:          getIntEnv("DEBUG", 0),
		ServerPort:     getIntEnv("SERVER_PORT", 8080),
		CACrtPath:      getStringEnv("CA_CERT_PATH", "/home/hannes/certs/ca.crt"),
		PrivateKeyPath: getStringEnv("PRIVATE_KEY_PATH", "/home/hannes/certs/key.key"),
	}
	return
}
