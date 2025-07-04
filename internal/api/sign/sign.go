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

package sign

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/core"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/utils"

	"github.com/cloudflare/cfssl/api"

	_ "crypto/x509"

	certdb "github.com/cloudflare/cfssl/certdb"
	cfssl_errors "github.com/cloudflare/cfssl/errors"
)

type Handler struct {
	DbAccessor    certdb.Accessor
	configuration config.Config
	signer        ocsp.Signer
}

// Only needed for swagger generation
type Result struct {
	Certifcate string `json:"certificate"`
}

func ParseRequestData(r *http.Request) (*model.SignRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	log.Debugf("Sign Request Data: %s", body)

	var signRequest model.SignRequest
	err = json.Unmarshal(body, &signRequest)
	if err != nil {
		log.Errorf("could not parse sign request: %s", err)
		return nil, errors.New("Unable to parse sign request")
	}

	if signRequest.Csr == "" {
		log.Errorf("CSR missing")
		return nil, errors.New("Unable to parse sign request: CRT is missing")
	}

	return &signRequest, nil
}

// Sign godoc
// @Summary      Sign a Certificate Signing Request
// @Description	 The provided certificate will be signed with the root CA certificate. The expiration time in hours will be used for the certificate expiration. The hostnames will be used for the subject alternative name field. The User ID will be used in the common name field.
// @Accept       json
// @Produce      json
// @Param        payload  body     model.SignRequest     true "Request payload"
// @Success      200 {object} x509.Certificate
// @Router       /sign [post]
func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("Signature request received")

	signRequest, err := ParseRequestData(r)
	if err != nil {
		log.Errorf("could not parse request data")
		return cfssl_errors.NewBadRequestString("Request parsing failed")
	}

	userId := utils.GetUserId(r)

	cert, err := core.Sign(userId, signRequest, handler.configuration, handler.DbAccessor, handler.signer)
	if err != nil {
		log.Errorf("cant sign request: %s", err)
		return cfssl_errors.NewBadRequestString("Signing failed")
	}
	_, err = w.Write(*cert)
	return err
}

func NewHandler(db certdb.Accessor, configuration config.Config, signer ocsp.Signer) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{
			DbAccessor:    db,
			configuration: configuration,
			signer:        signer,
		},
		Methods: []string{"POST"},
	}
}
