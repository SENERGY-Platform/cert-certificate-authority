package sign

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/log"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/core"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"

	"github.com/cloudflare/cfssl/api"

	certdb "github.com/cloudflare/cfssl/certdb"
	cfssl_errors "github.com/cloudflare/cfssl/errors"
)

type Handler struct {
	DbAccessor    certdb.Accessor
	configuration config.Config
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

	if signRequest.Crt == "" {
		log.Errorf("CSR missing")
		return nil, errors.New("Unable to parse sign request: CRT is missing")
	}

	return &signRequest, nil
}

// ShowAccount godoc
// @Summary      Sign a Certificate Signing Request
// @Description	 The provided certificate will be signed with the root CA certificate. The expiration time in hours will be used for the certificate expiration. The hostnames will be used for the subject alternative name field. The User ID will be used in the common name field.
// @Accept       json
// @Produce      json
// @Param        payload  body     model.SignRequest     true "Request payload"
// @Success      200 {object} Result
// @Router       /sign [post]
func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("Signature request received")

	signRequest, err := ParseRequestData(r)
	if err != nil {
		log.Errorf("could not parse request data")
		return cfssl_errors.NewBadRequestString("Request parsing failed")
	}

	userName := r.Header.Get("X-UserId")

	cert, err := core.Sign(userName, signRequest, handler.configuration, handler.DbAccessor)
	if err != nil {
		log.Errorf("cant sign request: %s", err)
		return cfssl_errors.NewBadRequestString("Signing failed")
	}
	result := map[string]string{"certificate": string(*cert)}

	return api.SendResponse(w, result)
}

func NewHandler(db certdb.Accessor, configuration config.Config) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{
			DbAccessor:    db,
			configuration: configuration,
		},
		Methods: []string{"POST"},
	}
}
