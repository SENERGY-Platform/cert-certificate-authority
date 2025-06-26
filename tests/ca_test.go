/*
 * Copyright 2025 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sign

import (
	"context"
	"crypto/x509/pkix"
	"net/http"
	"testing"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/db"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/server"
	"github.com/SENERGY-Platform/cert-certificate-authority/pkg/client"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ocsp"
)

func TestCertificates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stack, err := compose.NewDockerCompose("../tests/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
		return
	}
	err = stack.WaitForService("db_init", wait.ForExit()).Up(ctx)
	if err != nil {
		t.Fatal(err)
		return
	}

	config, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.SignbackDuration = time.Second
	config.DBDatabase = "db"
	config.DBAddr = "127.0.0.1:8081"
	config.DBPassword = "password"
	config.DBUser = "user"
	config.CACrtPath = "../tests/certs/ca.crt"
	config.PrivateKeyPath = "../tests/certs/key.key"

	dbConnection, err := db.GetDB(config)
	if err != nil {
		t.Fatalf("can not connect to DB: %s", err)
		return
	}
	go func() {
		server.StartServer(ctx, dbConnection, config)
	}()

	// This tests the signing process of valid CSRs and checks the returned certifactes
	tt := []struct {
		name       string        // Test name
		crtCN      string        // Common Name value in CSR
		expiration time.Duration // expiration in hours that is used in the sign request
		hostnames  []string      // hostnames that are used in the sign request that will be set in the SAN field
	}{
		{
			name:       "valid csr - short expiration",
			crtCN:      "admin",
			expiration: time.Hour,
			hostnames:  []string{"localhost"},
		},
		{
			name:       "valid csr - long expiration",
			crtCN:      "admin",
			expiration: 300 * time.Hour,
			hostnames:  []string{"localhost"},
		},
	}

	client := client.NewClient("http://localhost:8080")

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, cert, code, err := client.NewCertAndKey(pkix.Name{
				CommonName: tc.crtCN,
			}, tc.hostnames, tc.expiration, nil)
			assertCodeErr(t, code, err)

			truncate := time.Hour // Signing date will be altered slightly by cfssl
			notAfter := cert.NotAfter.Truncate(truncate)
			expectedNotAfter := time.Now().Add(tc.expiration).Truncate(truncate)

			if !expectedNotAfter.Equal(notAfter) {
				t.Errorf("Expiration time not matching. Want %v - Got %v", expectedNotAfter, notAfter)
				return
			}

			cn := cert.Subject.CommonName
			if cn != "testUser" {
				t.Errorf("Certificate Common Name field not matching. Want %s - Got %s", "testUser", cn)
				return
			}

			expired, ocspResp, code, err := client.GetStatus(cert, nil)
			assertCodeErr(t, code, err)
			if expired {
				t.Errorf("Cert status unexpectedly expired.")
				return
			}
			if ocspResp.Status != ocsp.Good {
				t.Errorf("OCSP status unexpected. Want %d - Got %d", ocsp.Good, ocspResp.Status)
				return
			} else {
				t.Log("OSCP looking good")
			}

			code, err = client.Revoke(cert, "Superseded", nil)
			assertCodeErr(t, code, err)
			code, err = client.Revoke(cert, "Superseded", nil)
			if err == nil && code == http.StatusOK {
				t.Errorf("Was able to revoke cert twice")
			}
			expired, ocspResp, code, err = client.GetStatus(cert, nil)
			if expired {
				t.Errorf("Cert status unexpectedly expired.")
			}
			assertCodeErr(t, code, err)
			if ocspResp.Status != ocsp.Revoked {
				t.Errorf("OCSP status unexpected. Want %d - Got %d", ocsp.Revoked, ocspResp.Status)
				return
			}

		})
	}
}

func assertCodeErr(t *testing.T, code int, err error) {
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
		return
	}

	if code != http.StatusOK {
		t.Fatalf("Want status '%d', got '%d'", http.StatusOK, code)
		return
	}
}
