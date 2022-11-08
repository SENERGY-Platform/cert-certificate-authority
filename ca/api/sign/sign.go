package sign

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/api"

	certdb "github.com/cloudflare/cfssl/certdb"
	cfssl_errors "github.com/cloudflare/cfssl/errors"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
)

type SignRequest struct {
	Crt        string   `json: crt`
	Expiration int      `json: expiration`
	Hostnames  []string `json: hostnames`
}

type Handler struct {
	Signer     signer.Signer
	DbAccessor certdb.Accessor
}

func ParseRequestData(r *http.Request) (*SignRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	var signRequest SignRequest
	err = json.Unmarshal(body, &signRequest)
	if err != nil {
		log.Printf("ERROR: could not parse sign request: %s", err)
		return nil, errors.New("Unable to parse sign request")
	}

	if signRequest.Crt == "" {
		log.Printf("ERROR: CSR missing")
		return nil, errors.New("Unable to parse sign request: CRT is missing")
	}

	return &signRequest, nil
}

func (h *Handler) Sign(r *http.Request, signRequest *SignRequest) (*[]byte, error) {
	userName := "sepl"
	sub := signer.Subject{
		CN: userName,
	}

	// Create the sign request, override SAN field with hostnames
	cfsslSignRequest := signer.SignRequest{
		Hosts:   signRequest.Hostnames,
		Subject: &sub,
		Request: signRequest.Crt,
	}

	cert, err := h.Signer.Sign(cfsslSignRequest)
	if err != nil {
		log.Printf("ERROR: failed to sign request: %v", err)
		return nil, err
	}

	return &cert, nil
}

func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Println("signature request received")

	signRequest, err := ParseRequestData(r)
	if err != nil {
		log.Println("ERROR: could not parse request data")
		return cfssl_errors.NewBadRequestString("Request parsing failed")
	}

	root := universal.Root{
		Config: map[string]string{
			"cert-file": "/etc/certs/ca.crt",
			"key-file":  "/etc/certs/key.key",
		},
	}

	// Create the signing policy with the wanted expiration time
	expString := strconv.Itoa(signRequest.Expiration)
	signProfile := config.SigningProfile{
		Usage:        []string{"client auth", "server auth"},
		Expiry:       time.Duration(signRequest.Expiration) * time.Hour,
		ExpiryString: expString + "h",
	}

	policy := config.Signing{
		Profiles: nil,
		Default:  &signProfile,
	}

	// Create the signer
	signMaker, err := universal.NewSigner(root, &policy)
	if err != nil {
		log.Printf("ERROR: setting up signer failed: %v", err)
		return cfssl_errors.NewBadRequestString("Creation of Signer failed")
	}

	signMaker.SetDBAccessor(handler.DbAccessor)
	handler.Signer = signMaker
	cert, err := handler.Sign(r, signRequest)
	if err != nil {
		log.Printf("ERROR: cant sign request: %s", err)
		return cfssl_errors.NewBadRequestString("Signing failed")
	}
	result := map[string]string{"certificate": string(*cert)}

	return api.SendResponse(w, result)
}

func NewHandler(db certdb.Accessor) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{
			DbAccessor: db,
		},
		Methods: []string{"POST"},
	}
}
