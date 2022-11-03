package ocsp

import (
	"log"
	"net/http"

	"ca/api"

	"github.com/cloudflare/cfssl/ocsp"
)

type Handler struct {
	signer ocsp.Signer
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Println("OCSP request received")
	return nil
}

func NewHandler() http.Handler {
	log.Println("Revoke certificate request received")
	return api.HTTPHandler{
		Handler: &Handler{},
		Methods: []string{"POST"},
	}
}
