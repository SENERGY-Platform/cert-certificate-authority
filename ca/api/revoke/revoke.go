package revoke

import (
	"log"
	"net/http"

	certsql "github.com/cloudflare/cfssl/certdb/sql"

	"ca/api"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/ocsp"
)

type Handler struct {
	dbAccessor certdb.Accessor
	Signer     ocsp.Signer
}

func NewHandler(db *certsql.Accessor) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: db,
		},
		Methods: []string{"POST"},
	}
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Println("Revoke certificate request received")
	return nil
}
