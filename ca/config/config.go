package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	ServerPort     int    `mapstructure: "SERVER_PORT"`
	DBDriver       string `mapstructure: "DB_DRIVER"`
	DBUser         string `mapstructure: "DB_USERNAME"`
	DBDatabase     string `mapstructure: "DB_DATABASE"`
	DBPassword     string `mapstructure: "DB_PASSWORD"`
	DBAddr         string `mapstructure: "DB_ADDR"`
	Debug          int    `mapstructure: "DEBUG"`
	CACrtPath      string `mapstructure: "CA_CERT_PATH"`
	PrivateKeyPath string `mapstructure: "PRIVATE_KEY_PATH"`
}

func LoadConfig() (config Config, err error) {
	viper.SetConfigType("env")
	viper.SetConfigFile("env")

	viper.AutomaticEnv()

	viper.SetDefault("DBDriver", "postgres")
	viper.SetDefault("DBUser", "user")
	viper.SetDefault("DBPassword", "password")
	viper.SetDefault("DBAddr", "db")
	viper.SetDefault("DBDatabase", "db")
	viper.SetDefault("Debug", 0)
	viper.SetDefault("ServerPort", 8080)
	viper.SetDefault("CACrtPath", "/etc/certs/ca.crt")
	viper.SetDefault("PrivateKeyPath", "/etc/certs/key.key")

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		log.Printf("ERROR: cant read config file: %s", err)
	}
	log.Printf("Configuration: %+v\n", config)

	return
}
