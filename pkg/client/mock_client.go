package client

import (
	"errors"
	"net/http"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"
)

type MockClient struct {
}

func NewMockClient() (client Client, err error) {
	client = &MockClient{}
	return
}

func (c *MockClient) Sign(commonName string, hostnames []string, expiration int) (signedCert *model.Response, err error, errCode int) {
	signedCert = &model.Response{
		Success:  true,
		Result:   model.CertificateResult{Certificate: "-----BEGIN CERTIFICATE-----\nMIIEPzCCA+SgAwIBAgIUVcZFvdL1Yc2TXY3kfE+nBAuAqdUwCgYIKoZIzj0EAwIw\ngYoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25k\nb24xFzAVBgNVBAoTDkN1c3RvbSBXaWRnZXRzMR0wGwYDVQQLExRDdXN0b20gV2lk\nZ2V0cyBIb3N0czEgMB4GA1UEAxMXaG9zdC5jdXN0b20td2lkZ2V0cy5jb20wHhcN\nMjMwMjI3MTMzOTAwWhcNMjMwMjI4MTMzOTAwWjBfMQswCQYDVQQGEwJBVTETMBEG\nA1UECBMKU29tZS1TdGF0ZTEMMAoGA1UEChMDb3JnMS0wKwYDVQQDEyRkZDY5ZWEw\nZC1mNTUzLTQzMzYtODBmMy03ZjQ1NjdmODVjN2IwggIiMA0GCSqGSIb3DQEBAQUA\nA4ICDwAwggIKAoICAQDFFWFSwXq5D5f12/Mw18rFuFq+21nNm//fv4SXayec9wa/\nlA/Gc/oYSbL0xMCrGWc4/99hogSp4XeIytJHUl44pFTcHdexn6908Vb6GxN7Kswm\nuAFmmaOu1LYruEZAhZjAZUn9VyQTACkUqHUHEI3p+jzl7QL0wO1MgPgi9Egy6bIR\nvrPQA/ea6Dv4KF/XfPDXoOCkivGbTpu05mdzW7Ap+jtwD+52HG3okwJB/eJWyX4F\nsPvjrE+eOy6vNVxRwauw1omrW6IGPqGwNd+g7R2PQj6tyaOFQ1qs9powrjb17abo\nv5wOwhVKjkfQOhunO+GQ8puLROHdyrz2Hudebjj4ToVNBR1pbjLJQmhh9YqEOxod\nofD4FMzGbKwa8LGCRSMriaCfA1DL2ATY8I48PsdM0UykfkOro1F/LpzumrkUek6t\nO0CKrOa1IrFlOsPBw5xkbTKabbVvPuzfaY28TVZUJEcv16m/V4p2l33pg2p0xpvg\nqt6l4/cwwunDtKWweP0ONcM6pSg97V2MhJUwAC+eUgTOxc63yqFeK8dEgGP8GR87\nQfr2mRW/zrY1hgnLL78/LK5HNj8SkzQEZAVJ6hGrc1XilSfHy9z3PluU2P9bUjuM\nbz86DID/QppNTr5t7Q+gQ8Ho+GtbUrtkuPaE8W9I6eLqE5VbCKOkAC4JFglEBQID\nAQABo4GGMIGDMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMB\nAf8EAjAAMB0GA1UdDgQWBBQC/mcISohWsDoHxG2xZoPczu7pRzAfBgNVHSMEGDAW\ngBTn+cMADvAY8MArXNbSGJHbm7hFiDAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYI\nKoZIzj0EAwIDSQAwRgIhAIRWRiIOtqWEGhG6FhYB3FuR42JJaLhYyZY+OsDJbEgb\nAiEAnAuijWQHzj5mC4mUR0Znf79cUH9DCT/wd/6BXpBEq/k=\n-----END CERTIFICATE-----\n"},
		Errors:   []model.ResponseMessage{model.ResponseMessage{Code: 200, Message: ""}},
		Messages: []model.ResponseMessage{model.ResponseMessage{Code: 200, Message: ""}},
	}
	return signedCert, nil, 0
}

func (c *MockClient) Revoke(serial string, authority_key_id string, reason string) (err error, errCode int) {
	if serial == "0" {
		return errors.New("Error"), http.StatusInternalServerError
	}
	return
}

func (c *MockClient) GetStatus(certificate string, status string) (ocsp *model.OCSPResponse, err error, errCode int) {
	ocspString := "MIIBpgoBAKCCAZ8wggGbBgkrBgEFBQcwAQEEggGMMIIBiDCCAS2hgY0wgYoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25kb24xFzAVBgNVBAoTDkN1c3RvbSBXaWRnZXRzMR0wGwYDVQQLExRDdXN0b20gV2lkZ2V0cyBIb3N0czEgMB4GA1UEAxMXaG9zdC5jdXN0b20td2lkZ2V0cy5jb20YDzIwMjMwMjI3MTUwNzAwWjCBiTCBhjBNMAkGBSsOAwIaBQAEFPrV+RrWDPtgcbhxno6XvaaV361kBBTn+cMADvAY8MArXNbSGJHbm7hFiAIUW+enFr00jqmR2fhUZPH4MRuo72ahERgPMjAyMzAyMjcxNTA3MjJaGA8yMDIzMDIyNzE1MDAwMFqgERgPMjAyMzAyMjcxNTAwMDBaMAoGCCqGSM49BAMCA0kAMEYCIQCtYKgR6EHY+hiZIkNfG4LL6K+WuGx47vM2hKd0cvQtZwIhANrFUAaqDeJqPAuHG5nnBoJjRHMkf1iFALomctZahiDO"
	ocsp = &model.OCSPResponse{
		Success:  true,
		Result:   model.OCSPResult{OCSPResponse: ocspString},
		Errors:   []model.ResponseMessage{model.ResponseMessage{Code: 200, Message: ""}},
		Messages: []model.ResponseMessage{model.ResponseMessage{Code: 200, Message: ""}},
	}
	return ocsp, nil, 0
}
