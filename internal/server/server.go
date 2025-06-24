package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/cfssl/log"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/ca"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/doc"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/list"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/revoke"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/api/sign"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/jmoiron/sqlx"
	cryptoocsp "golang.org/x/crypto/ocsp"
)

type NilStats struct{}

func (_ *NilStats) ResponseStatus(cryptoocsp.ResponseStatus) {}

var endpoints = map[string]func(db *sqlx.DB, configuration config.Config) (http.Handler, error){
	"/doc": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return doc.NewHandler(certsql.NewAccessor(db), configuration), nil
	},
	"/sign": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		ocspSigner, err := ocsp.NewSignerFromFile(configuration.CACrtPath, configuration.CACrtPath, configuration.PrivateKeyPath, 2*configuration.OCSPCycle)
		if err != nil {
			log.Errorf("cant setup ocsp signer: %s", err)
			return nil, err
		}
		return sign.NewHandler(certsql.NewAccessor(db), configuration, ocspSigner), nil
	},
	"/revoke": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		ocspSigner, err := ocsp.NewSignerFromFile(configuration.CACrtPath, configuration.CACrtPath, configuration.PrivateKeyPath, 2*configuration.OCSPCycle)
		if err != nil {
			log.Errorf("cant setup ocsp signer: %s", err)
			return nil, err
		}
		return revoke.NewOCSPHandler(certsql.NewAccessor(db), ocspSigner), nil
	},
	"/ocsp": func(db *sqlx.DB, configuration config.Config) (http.Handler, error) {
		return ocsp.NewResponder(ocsp.NewDBSource(certsql.NewAccessor(db)), &NilStats{}), nil
	},
	"/ca": func(_ *sqlx.DB, configuration config.Config) (http.Handler, error) {
		content, err := os.ReadFile(configuration.CACrtPath)
		if err != nil {
			log.Errorf("cant read CA file: %s", err)
			return nil, err
		}
		return ca.NewHandler(content), nil
	},
	"/list": func(db *sqlx.DB, _ config.Config) (http.Handler, error) {
		return list.NewHandler(db), nil
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

func StartServer(ctx context.Context, db *sqlx.DB, configuration config.Config) {
	err := startOCSPRefresh(db, configuration)
	if err != nil {
		log.Errorf("can not StartOCSPRefresh: %s", err)
		os.Exit(1)
	}

	err = registerHandlers(db, configuration)
	if err != nil {
		log.Errorf("error starting server: %s\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: ":8080"}

	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = srv.Shutdown(ctx2)
		if err != nil {
			log.Errorf("Error shutting down server: %v", err)
		}
	}()

	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		log.Errorf("server closed\n")
	} else if err != nil {
		log.Errorf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
