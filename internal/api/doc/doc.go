package doc

import (
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/api"
	certdb "github.com/cloudflare/cfssl/certdb"
	"github.com/swaggo/swag"

	_ "github.com/SENERGY-Platform/cert-certificate-authority/docs"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
)

type Handler struct {
}

func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	doc, err := swag.ReadDoc()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	//remove empty host to enable developer-swagger-api service to replace it; can not use cleaner delete on json object, because developer-swagger-api is sensible to formatting; better alternative is refactoring of developer-swagger-api/apis/db/db.py
	doc = strings.Replace(doc, `"host": "",`, "", 1)
	_, _ = w.Write([]byte(doc))
	return nil
}

func NewHandler(db certdb.Accessor, configuration config.Config) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{},
		Methods: []string{"GET"},
	}
}
