package client

import "github.com/SENERGY-Platform/cert-certificate-authority/internal/model"

type Client interface {
	Sign(commonName string, hostnames []string, expiration int) (signedCert *model.Response, err error, errCode int)
	Revoke(serial string, authority_key_id string, reason string) (err error, errCode int)
	GetStatus(certificate string, status string) (ocsp *model.OCSPResponse, err error, errCode int)
}
