/*
 * Copyright 2025 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
