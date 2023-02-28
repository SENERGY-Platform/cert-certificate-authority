package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

func DecodeCertificate(certString string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certString))
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

func EncodeCertificateRequest(commonName string, hostnames []string) (certString string, err error) {
	csr := CreateCertificateSigningRequest(commonName, hostnames)
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csr, keyBytes)
	var PublicKeyRow bytes.Buffer
	pem.Encode(&PublicKeyRow, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	certString = PublicKeyRow.String()
	return
}

func CreateCertificateSigningRequest(commonName string, hostnames []string) x509.CertificateRequest {
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
