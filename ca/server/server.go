package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"ca/api/sign"
	"ca/config"

	ocspApi "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/revoke"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/jmoiron/sqlx"
)

var endpoints = map[string]func(db *sqlx.DB, configuration config.Config) (http.Handler, error){
	"/sign": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return sign.NewHandler(certsql.NewAccessor(db), configuration), nil
	},
	"/revoke": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return revoke.NewHandler(certsql.NewAccessor(db)), nil
	},
	"/ocsp": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		ocspSigner, err := ocsp.NewSignerFromFile(configuration.CACrtPath, configuration.CACrtPath, configuration.PrivateKeyPath, time.Duration(96))

		if err != nil {
			log.Printf("ERROR: %s", err)
			return nil, err
		}
		return ocspApi.NewHandler(ocspSigner), nil

	},
}

func registerHandlers(db *sqlx.DB, configuration config.Config) error {
	for path, getHandler := range endpoints {
		handler, err := getHandler(db, configuration)
		if err != nil {
			return err
		}
		http.Handle(path, handler)
	}
	return nil
}

func StartServer(db *sqlx.DB, configuration config.Config) {
	err := registerHandlers(db, configuration)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}

	err = http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
