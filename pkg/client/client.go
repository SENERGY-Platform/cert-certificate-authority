package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/utils"
	"golang.org/x/crypto/ocsp"
)

type RealClient struct {
	baseUrl string
	ca      *x509.Certificate
}

func NewClient(baseUrl string) (client Client) {
	client = &RealClient{
		baseUrl: baseUrl,
	}
	return
}

func (c *RealClient) NewCertAndKey(subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (privateKey *rsa.PrivateKey, cert *x509.Certificate, errCode int, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	cert, code, err := c.NewCertFromKey(privateKey, subj, hostnames, expiration, token)
	return privateKey, cert, code, err
}

func (c *RealClient) NewCertFromKey(privateKey *rsa.PrivateKey, subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (cert *x509.Certificate, errCode int, err error) {
	csr, err := utils.EncodeCertificateRequest(privateKey, subj)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	data := model.SignRequest{
		Csr:        csr,
		Expiration: expiration.String(),
		Hostnames:  hostnames,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/sign", strings.NewReader(string(body)))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	b, code, err := doWithBinaryResponse(req, token)
	if err != nil {
		return nil, code, err
	}
	block, _ := pem.Decode(b)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, code, err
	}
	return cert, code, err
}

func (c *RealClient) Revoke(cert *x509.Certificate, reason string, token *string) (errCode int, err error) {
	if cert == nil {
		return http.StatusBadRequest, fmt.Errorf("cert can't be nil")
	}
	data := model.Revocation{
		Serial:           cert.SerialNumber.String(),
		Authority_key_id: hex.EncodeToString(cert.AuthorityKeyId),
		Reason:           reason,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/revoke", strings.NewReader(string(body)))
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return do(req, token)
}

func (c *RealClient) GetStatus(cert *x509.Certificate, token *string) (expired bool, resp *ocsp.Response, code int, err error) {
	expired = cert.NotAfter.Before(time.Now())
	if expired {
		return expired, nil, http.StatusOK, err
	}
	ca, _, err := c.GetCA(token)
	if err != nil {
		return expired, nil, http.StatusInternalServerError, err
	}
	body, err := ocsp.CreateRequest(cert, ca, nil)
	if err != nil {
		return expired, nil, http.StatusInternalServerError, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/ocsp", strings.NewReader(string(body)))
	if err != nil {
		return expired, nil, http.StatusInternalServerError, err
	}
	b, code, err := doWithBinaryResponse(req, token)
	if err != nil {
		return expired, nil, code, err
	}
	resp, err = ocsp.ParseResponse(b, ca)
	return expired, resp, code, err
}

func (c *RealClient) GetCA(token *string) (cert *x509.Certificate, errCode int, err error) {
	if c.ca != nil && time.Now().Before(c.ca.NotAfter) {
		return c.ca, http.StatusOK, nil
	}
	req, err := http.NewRequest(http.MethodGet, c.baseUrl+"/ca", nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	b, code, err := doWithBinaryResponse(req, token)
	if err != nil {
		return nil, code, err
	}
	block, _ := pem.Decode(b)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, code, err
	}
	c.ca = cert
	return cert, code, err
}

func doWithBinaryResponse(req *http.Request, token *string) (result []byte, code int, err error) {
	if token != nil {
		req.Header.Set("Authorization", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return result, http.StatusInternalServerError, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		temp, _ := io.ReadAll(resp.Body) //read error response end ensure that resp.Body is read to EOF
		return result, resp.StatusCode, fmt.Errorf("unexpected statuscode %v: %v", resp.StatusCode, string(temp))
	}
	code = resp.StatusCode
	result, err = io.ReadAll(resp.Body)

	return
}

func do(req *http.Request, token *string) (code int, err error) {
	if token != nil {
		req.Header.Set("Authorization", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return resp.StatusCode, nil
}
