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

package core

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"

	"crypto/x509"

	"github.com/cloudflare/cfssl/certdb"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	cfssl_errors "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
	stdocsp "golang.org/x/crypto/ocsp"
)

func Sign(userName string, signRequest *model.SignRequest, configuration config.Config, db certdb.Accessor, ocspSigner ocsp.Signer) (*[]byte, error) {
	root := universal.Root{
		Config: map[string]string{
			"cert-file": configuration.CACrtPath,
			"key-file":  configuration.PrivateKeyPath,
		},
	}

	// Create the signing policy with the wanted expiration time
	d, err := time.ParseDuration(signRequest.Expiration)
	if err != nil {
		return nil, cfssl_errors.NewBadRequestString(fmt.Sprintf("Unable to parse expiration %v", err))
	}
	if d > time.Hour*24*365 || d < time.Hour {
		return nil, cfssl_errors.NewBadRequestString("Illegal expiration! Should be between 1 hour and 1 year")
	}

	signProfile := cfsslConfig.SigningProfile{
		Usage:    []string{"client auth", "server auth"},
		Expiry:   d,
		Backdate: configuration.SignbackDuration,
	}

	policy := cfsslConfig.Signing{
		Profiles: nil,
		Default:  &signProfile,
	}

	// Create the signer
	signMaker, err := universal.NewSigner(root, &policy)
	if err != nil {
		log.Errorf("setting up signer failed: %v", err)
		return nil, cfssl_errors.NewBadRequestString("Creation of Signer failed")
	}

	signMaker.SetDBAccessor(db)

	sub := signer.Subject{
		CN: userName,
	}

	// Create the sign request, override SAN field with hostnames
	cfsslSignRequest := signer.SignRequest{
		Hosts:    signRequest.Hostnames,
		Subject:  &sub,
		Request:  signRequest.Csr,
		Metadata: map[string]interface{}{"Hostnames": signRequest.Hostnames},
	}

	cert, err := signMaker.Sign(cfsslSignRequest)
	if err != nil {
		log.Errorf("failed to sign request: %v", err)
		return nil, err
	}

	block, _ := pem.Decode(cert)
	xCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Errorf("failed to parse cert: %v", err)
		return nil, err
	}
	now := time.Now()
	expires := now.Add(2 * configuration.OCSPCycle)
	sr := ocsp.SignRequest{
		Certificate: xCert,
		Status:      "good",
		ThisUpdate:  &now,
		NextUpdate:  &expires,
	}

	ocspResponse, err := ocspSigner.Sign(sr)
	if err != nil {
		return nil, err
	}

	// We parse the OCSP response in order to get the next
	// update time/expiry time
	ocspParsed, err := stdocsp.ParseResponse(ocspResponse, nil)
	if err != nil {
		return nil, err
	}

	ocspRecord := certdb.OCSPRecord{
		Serial: xCert.SerialNumber.String(),
		AKI:    hex.EncodeToString(xCert.AuthorityKeyId),
		Body:   string(ocspResponse),
		Expiry: ocspParsed.NextUpdate,
	}

	err = db.InsertOCSP(ocspRecord)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
