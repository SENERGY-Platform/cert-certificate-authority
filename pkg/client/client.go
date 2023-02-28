package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/utils"
)

type RealClient struct {
	baseUrl string
}

func NewClient(baseUrl string) (client Client, err error) {
	client = &RealClient{
		baseUrl: baseUrl,
	}
	return
}

func (c *RealClient) Sign(commonName string, hostnames []string, expiration int) (signedCert *model.Response, err error, errCode int) {
	crt, err := utils.EncodeCertificateRequest(commonName, hostnames)

	data := model.SignRequest{
		Crt:        crt,
		Expiration: expiration,
		Hostnames:  hostnames,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, err, http.StatusInternalServerError
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/sign", strings.NewReader(string(body)))
	if err != nil {
		return nil, err, http.StatusInternalServerError
	}
	return doWithResponse[*model.Response](req)
}

func (c *RealClient) Revoke(serial string, authority_key_id string, reason string) (err error, errCode int) {
	data := model.Revocation{
		Serial:           serial,
		Authority_key_id: authority_key_id,
		Reason:           reason,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/revoke", strings.NewReader(string(body)))
	if err != nil {
		return err, http.StatusInternalServerError
	}
	return do(req)
}

func (c *RealClient) GetStatus(certificate string, status string) (ocsp *model.OCSPResponse, err error, errCode int) {
	data := model.OCSP{
		Certificate: certificate,
		Status:      status,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return &model.OCSPResponse{}, err, http.StatusInternalServerError
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/ocsp", strings.NewReader(string(body)))
	if err != nil {
		return &model.OCSPResponse{}, err, http.StatusInternalServerError
	}
	return doWithResponse[*model.OCSPResponse](req)
}

func doWithResponse[T any](req *http.Request) (result T, err error, code int) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return result, err, http.StatusInternalServerError
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		temp, _ := io.ReadAll(resp.Body) //read error response end ensure that resp.Body is read to EOF
		return result, fmt.Errorf("unexpected statuscode %v: %v", resp.StatusCode, string(temp)), resp.StatusCode
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		_, _ = io.ReadAll(resp.Body) //ensure resp.Body is read to EOF
		return result, err, http.StatusInternalServerError
	}
	return
}

func do(req *http.Request) (err error, code int) {
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		return err, http.StatusInternalServerError
	}
	return
}
