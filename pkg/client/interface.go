package client

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"golang.org/x/crypto/ocsp"
)

type Client interface {
	// Creates a CSR from a new key and sends it to the CA. Can use a token with Prefix "Bearer " for authentication. Expects authentication via proxy if token is nil.
	NewCertAndKey(subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (privateKey *rsa.PrivateKey, cert *x509.Certificate, errCode int, err error)

	// Creates a CSR from an existing key and sends it to the CA. Can use a token with Prefix "Bearer " for authentication. Expects authentication via proxy if token is nil.
	NewCertFromKey(privateKey *rsa.PrivateKey, subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (cert *x509.Certificate, errCode int, err error)

	// Revokes the given cert at the CA. Can use a token with Prefix "Bearer " for authentication. Expects authentication via proxy if token is nil.
	Revoke(cert *x509.Certificate, reason string, token *string) (errCode int, err error)

	// Checks if the certificate is expired. If not, queries the status of the given Certifiacte at the CA using OCSP. Can use a token with Prefix "Bearer " for authentication. Expects authentication via proxy if token is nil.
	GetStatus(cert *x509.Certificate, token *string) (expired bool, ocsp *ocsp.Response, errCode int, err error)

	// Gets the public CA certificate. Can use a token with Prefix "Bearer " for authentication. Expects authentication via proxy if token is nil.
	GetCA(token *string) (cert *x509.Certificate, errCode int, err error)
}
