package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"ca/api/sign"

	ocspApi "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/revoke"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/jmoiron/sqlx"
)

var endpoints = map[string]func(db *sqlx.DB) (http.Handler, error){
	"/sign": func(db *sqlx.DB) (http.Handler, error) {
		return sign.NewHandler(certsql.NewAccessor(db)), nil
	},
	"/revoke": func(db *sqlx.DB) (http.Handler, error) {
		return revoke.NewHandler(certsql.NewAccessor(db)), nil
	},
	"/ocsp": func(db *sqlx.DB) (http.Handler, error) {
		ocspSigner, err := ocsp.NewSignerFromFile("/etc/certs/ca.crt", "/etc/certs/ca.crt", "/etc/certs/key.key", time.Duration(96))

		if err != nil {
			log.Printf("ERROR: %s", err)
			return nil, err
		}
		return ocspApi.NewHandler(ocspSigner), nil

	},
}

func registerHandlers(db *sqlx.DB) {
	for path, getHandler := range endpoints {
		handler, err := getHandler(db)
		if err == nil {
			log.Printf("endpoint '%s' is enabled", path)
			http.Handle(path, handler)
		} else {
			log.Printf("endpoint '%s' is disabled: %s", path, err)
		}

	}
}

func StartServer(db *sqlx.DB) {
	registerHandlers(db)

	err := http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
