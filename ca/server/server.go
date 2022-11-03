package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"ca/api/ocsp"
	"ca/api/revoke"
	"ca/api/sign"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/jmoiron/sqlx"
)

var endpoints = map[string]func(db *sqlx.DB) http.Handler{
	"/sign": func(db *sqlx.DB) http.Handler {
		return sign.NewHandler()
	},
	"/revoke": func(db *sqlx.DB) http.Handler {
		return revoke.NewHandler(certsql.NewAccessor(db))
	},
	"/ocsp": func(db *sqlx.DB) http.Handler {
		return ocsp.NewHandler()
	},
}

func registerHandlers(db *sqlx.DB) {
	for path, getHandler := range endpoints {
		handler := getHandler(db)
		log.Println("endpoint '%s' is enabled", path)
		http.Handle(path, handler)
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
