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
