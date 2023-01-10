package doc

import (
	"net/http"

	"github.com/cloudflare/cfssl/api"
	certdb "github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"

	"ca/internal/config"
)

type Handler struct {
}

func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("Doc request received")
	http.ServeFile(w, r, "swagger.json")
	return nil
}

func NewHandler(db certdb.Accessor, configuration config.Config) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{},
		Methods: []string{"GET"},
	}
}
