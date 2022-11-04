package sign

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	"ca/api"

	certdb "github.com/cloudflare/cfssl/certdb"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
)

type SignRequest struct {
	Crt        string   `json: crt`
	Expiration string   `json: expiration`
	Hostnames  []string `json: hostnames`
}

type Handler struct {
	signer     signer.Signer
	dbAccessor certdb.Accessor
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
		return nil, errors.New("Unable to parse sign request")
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

	cert, err := h.signer.Sign(cfsslSignRequest)
	if err != nil {
		log.Println("failed to sign request: %v", err)
		return nil, err
	}

	return &cert, nil
}

func (handler *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Println("signature request received")

	signRequest, err := ParseRequestData(r)

	root := universal.Root{
		Config: map[string]string{
			"cert-file": "/etc/certs/ca.crt",
			"key-file":  "/etc/certs/key.key",
		},
	}

	// Create the signing policy with the wanted expiration time
	signProfile := config.DefaultConfig()
	(*signProfile).ExpiryString = signRequest.Expiration
	(*signProfile).Usage = []string{"client auth", "server auth"}
	(*signProfile).OCSP = "TODO"

	policy := config.Signing{
		Profiles: nil,
		Default:  signProfile,
	}

	// Create the signer
	signMaker, err := universal.NewSigner(root, &policy)
	if err != nil {
		log.Println("setting up signer failed: %v", err)
		return err
	}

	signMaker.SetDBAccessor(handler.dbAccessor)
	handler.signer = signMaker
	cert, err := handler.Sign(r, signRequest)
	result := map[string]string{"certificate": string(*cert)}

	log.Println("wrote response")
	return api.SendResponse(w, result)
}

func NewHandler(db certdb.Accessor) http.Handler {
	return api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: db,
		},
		Methods: []string{"POST"},
	}
}
