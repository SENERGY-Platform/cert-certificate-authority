package test

import (
	"ca/api/sign"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// "-----BEGIN CERTIFICATE REQUEST-----\n\nMIIEhTCCAm0CAQAwQDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n\nDDAKBgNVBAoMA29yZzEOMAwGA1UEAwwFYWRtaW4wggIiMA0GCSqGSIb3DQEBAQUA\n\nA4ICDwAwggIKAoICAQDFFWFSwXq5D5f12/Mw18rFuFq+21nNm//fv4SXayec9wa/\n\nlA/Gc/oYSbL0xMCrGWc4/99hogSp4XeIytJHUl44pFTcHdexn6908Vb6GxN7Kswm\n\nuAFmmaOu1LYruEZAhZjAZUn9VyQTACkUqHUHEI3p+jzl7QL0wO1MgPgi9Egy6bIR\n\nvrPQA/ea6Dv4KF/XfPDXoOCkivGbTpu05mdzW7Ap+jtwD+52HG3okwJB/eJWyX4F\n\nsPvjrE+eOy6vNVxRwauw1omrW6IGPqGwNd+g7R2PQj6tyaOFQ1qs9powrjb17abo\n\nv5wOwhVKjkfQOhunO+GQ8puLROHdyrz2Hudebjj4ToVNBR1pbjLJQmhh9YqEOxod\n\nofD4FMzGbKwa8LGCRSMriaCfA1DL2ATY8I48PsdM0UykfkOro1F/LpzumrkUek6t\n\nO0CKrOa1IrFlOsPBw5xkbTKabbVvPuzfaY28TVZUJEcv16m/V4p2l33pg2p0xpvg\n\nqt6l4/cwwunDtKWweP0ONcM6pSg97V2MhJUwAC+eUgTOxc63yqFeK8dEgGP8GR87\n\nQfr2mRW/zrY1hgnLL78/LK5HNj8SkzQEZAVJ6hGrc1XilSfHy9z3PluU2P9bUjuM\n\nbz86DID/QppNTr5t7Q+gQ8Ho+GtbUrtkuPaE8W9I6eLqE5VbCKOkAC4JFglEBQID\n\nAQABoAAwDQYJKoZIhvcNAQELBQADggIBAC6pxAIHNFGe5qT4WvqzaY9bhkO27qWL\n\neOeYammnM63RjGpSAzPyreqaAq4zf0bdnfJ0WrGd+MV75oyVsTAxqaVMrWHy5c13\n\nQcIwccvqp/7Pzo//UVKVtxajU3xDDdjaB+Ng8TxAjSDS3hmwUlcQkVuNPbTatG9t\n\nKZQYX0g7Wm2im1l6NwJG9EczjT11VJkLqhbsHx22m20C1O3X2JZy9xxx+Gsi9b2f\n\n7GQAQ/m7313w/AuN/AMkrnO19iPCD9zcDlsvjDm6m72gADVht+XPkvZ9+T3GmdZv\n\nbyD/ZpgnuEMhccz5+6Uri3LcBwGou7r0R+hDLAI29YZm/zY7uNDP8twnbKsrJkp7\n\niHZvMyTVL++tpAGv2Ztpw6QO48gsJhRitD88atvMn7PzGvpnMZ4K3h1JioUyvF6V\n\nBvdlDDt00XA71dUa2S8Wwi9AbBH0nJ5q8f5r1w9leeT4bMPCnSPAbKs+VF5dCInk\n\nP32dgc0C0hzWvrod4fzgcGU/JE5uCGTEktf+AGh4EPUhwKGRNh78Qts85nVVAPLy\n\n9YJIIOdTcktye1j2glr7wc6f3grTgB0JwKQzRHDDHDIkC1pexawUcDTo8+RP5F5T\n\nDEwdgmXavwJXFPSE1dZbBowX4QKXfDGvDckZg2336SUoTS1KzZNS8o2nL0pYNVKo\n\nfjgZ6fnblEXr\n\n-----END CERTIFICATE REQUEST-----",

func TestSigningCertificates(t *testing.T) {
	// This tests the signing process of valid CSRs and checks the returned certifactes
	tt := []struct {
		name       string   // Test name
		crtCN      string   // Common Name value in CSR
		user       string   // simulated user name that is authenticated normally. This will be set in the Common Name field of the cert
		expiration int      // expiration in hours that is used in the sign request
		hostnames  []string // hostnames that are used in the sign request that will be set in the SAN field
	}{
		{
			name:       "valid csr - short expiration",
			crtCN:      "admin",
			user:       "user1",
			expiration: 24,
			hostnames:  []string{"localhost"},
		},
		{
			name:       "valid csr - long expiration",
			crtCN:      "admin",
			expiration: 300,
			user:       "user2",
			hostnames:  []string{"localhost"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			crt, err := encodeCertificateRequest(tc.crtCN, []string{"admin.de"})

			data := sign.SignRequest{
				Crt:        crt,
				Expiration: tc.expiration,
				Hostnames:  tc.hostnames,
			}

			body, err := json.Marshal(data)
			if err != nil {
				t.Errorf("cant marshal test data: %s", err)
			}

			bodyString := string(body)
			responseRecorder, err := makeSignRequest(http.MethodPost, &bodyString, tc.user)
			if err != nil {
				t.Errorf("could not make request: %s", err)
			}

			if responseRecorder.Code != http.StatusOK {
				t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
			}

			var response Response
			err = json.Unmarshal([]byte(responseRecorder.Body.String()), &response)
			if err != nil {
				t.Errorf("cant unmarshal response")
			}

			if response.Success != true {
				t.Errorf("expected success")
			}

			parsedCert, err := decodeCertificate(response.Result.Certificate)
			if err != nil {
				t.Errorf("Could not decode certificate")
			}

			// Expiration is done on hour level
			oneDay := 24 * time.Hour
			notAfter := parsedCert.NotAfter
			expectedNotAfter := time.Now().Add(time.Hour * time.Duration(tc.expiration))
			notAfter = notAfter.Truncate(oneDay)
			expectedNotAfter = expectedNotAfter.Truncate(oneDay)

			if !expectedNotAfter.Equal(notAfter) {
				t.Errorf("Expiration time not matching. Want %v - Got %v", expectedNotAfter, notAfter)
			}

			cn := parsedCert.Subject.CommonName
			if cn != tc.user {
				t.Errorf("Certificate Common Name field not matching. Want %s - Got %s", tc.user, cn)
			}
		})
	}
}

func TestSigningMessages(t *testing.T) {
	// This tests the signing process of invalid requests and checks the returned messages

	tt := []struct {
		name       string
		method     string
		data       *sign.SignRequest
		want       string
		statusCode int
	}{
		{
			name:       "wrong method",
			method:     http.MethodGet,
			data:       nil,
			want:       `{"success":false,"result":null,"errors":[{"code":405,"message":"Method is not allowed:\"GET\""}],"messages":[]}`,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:   "missing crt",
			method: http.MethodPost,
			data: &sign.SignRequest{
				Crt:        "",
				Expiration: 24,
				Hostnames:  []string{"localhost"},
			},
			want:       `{"success":false,"result":null,"errors":[{"code":400,"message":"Request parsing failed"}],"messages":[]}`,
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			user := "user"
			var responseRecorder *httptest.ResponseRecorder
			var err error

			if tc.method == http.MethodPost {
				body, err := json.Marshal(*tc.data)
				if err != nil {
					t.Errorf("cant marshal test data: %s", err)
				}

				bodyString := string(body)
				responseRecorder, err = makeSignRequest(tc.method, &bodyString, user)
			} else {
				responseRecorder, err = makeSignRequest(tc.method, nil, user)
			}

			if err != nil {
				t.Errorf("could not make request")
			}

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}
