package test

import (
	"bytes"
	"ca/internal/config"
	"ca/internal/db"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
)

type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CertificateResult struct {
	Certificate string `json:"certificate"`
}

type Response struct {
	Success  bool              `json:"success"`
	Result   CertificateResult `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}

func getTestDB(configuration config.Config) (acc *certsql.Accessor, err error) {
	db, err := db.GetDB(configuration)
	if err != nil {
		log.Printf("ERROR: can not connect to DB: %s", err)
		return
	}
	acc = certsql.NewAccessor(db)
	return
}

func decodeCertificate(certString string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certString))
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

func encodeCertificateRequest(commonName string, hostnames []string) (certString string, err error) {
	csr := createCertificateSigningRequest(commonName, hostnames)
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csr, keyBytes)
	var PublicKeyRow bytes.Buffer
	pem.Encode(&PublicKeyRow, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	certString = PublicKeyRow.String()
	return
}

func createCertificateSigningRequest(commonName string, hostnames []string) x509.CertificateRequest {
	subj := pkix.Name{
		CommonName:         commonName,
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return template
}
