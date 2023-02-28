package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/cfssl/log"
	// @Param        payload  body     SignRequest     true "Request payload"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/doc"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/sign"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"

	ocspApi "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/revoke"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/jmoiron/sqlx"
)

var endpoints = map[string]func(db *sqlx.DB, configuration config.Config) (http.Handler, error){
	"/doc": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return doc.NewHandler(certsql.NewAccessor(db), configuration), nil
	},
	"/sign": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return sign.NewHandler(certsql.NewAccessor(db), configuration), nil
	},
	"/revoke": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return revoke.NewHandler(certsql.NewAccessor(db)), nil
	},
	"/ocsp": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		ocspSigner, err := ocsp.NewSignerFromFile(configuration.CACrtPath, configuration.CACrtPath, configuration.PrivateKeyPath, time.Duration(96))

		if err != nil {
			log.Errorf("cant setup ocsp signer: %s", err)
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
		fmt.Errorf("error starting server: %s\n", err)
		os.Exit(1)
	}

	err = http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		log.Errorf("server closed\n")
	} else if err != nil {
		log.Errorf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
