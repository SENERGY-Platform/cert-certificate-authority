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

	userName := r.Header.Get("X-UserId")
	if userName == "" {
		userName = "testUser"
		log.Warningf("No header X-UserId set. Assuming test environment. Setting username to %v", userName)
	}

	cert, err := core.Sign(userName, signRequest, handler.configuration, handler.DbAccessor, handler.signer)
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
