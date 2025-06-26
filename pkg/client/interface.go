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
