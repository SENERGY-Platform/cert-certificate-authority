package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/cloudflare/cfssl/log"
	"net/http"
)

func DecodeCertificate(certString string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certString))
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

func EncodeCertificateRequest(privateKey *rsa.PrivateKey, subj pkix.Name) (certString string, err error) {
	csr := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
	if err != nil {
		return "", err
	}
	var PublicKeyRow bytes.Buffer
	pem.Encode(&PublicKeyRow, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	certString = PublicKeyRow.String()
	return
}

func GetUserId(r *http.Request) string {
	userId := r.Header.Get("X-UserId")
	if userId == "" {
		userId = "testUser"
		log.Warningf("No header X-UserId set. Assuming test environment. Setting username to %v", userId)
	}
	return userId
}
