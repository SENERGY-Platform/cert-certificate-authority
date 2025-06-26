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

package server

import (
	"encoding/hex"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/jmoiron/sqlx"
)

func startOCSPRefresh(db *sqlx.DB, configuration config.Config) error {
	dbAccessor := certsql.NewAccessor(db)
	signer, err := ocsp.NewSignerFromFile(configuration.CACrtPath, configuration.CACrtPath, configuration.PrivateKeyPath, 2*configuration.OCSPCycle)
	if err != nil {
		log.Errorf("cant setup ocsp signer: %s", err)
		return err
	}
	go func() {
		ticker := time.NewTicker(configuration.OCSPCycle)
		ocspRefresh := func() {
			certs, err := dbAccessor.GetUnexpiredCertificates()
			if err != nil {
				log.Critical("Unable to GetUnexpiredCertificates: ", err)
				return
			}

			// Set an expiry timestamp for all certificates refreshed in this batch
			ocspExpiry := time.Now().Add(2 * configuration.OCSPCycle)
			for _, certRecord := range certs {
				cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM))
				if err != nil {
					log.Critical("Unable to parse certificate: ", err)
					continue
				}

				req := ocsp.SignRequest{
					Certificate: cert,
					Status:      certRecord.Status,
				}

				if certRecord.Status == "revoked" {
					req.Reason = int(certRecord.Reason)
					req.RevokedAt = certRecord.RevokedAt
				}

				resp, err := signer.Sign(req)
				if err != nil {
					log.Critical("Unable to sign OCSP response: ", err)
					continue
				}

				err = dbAccessor.UpsertOCSP(cert.SerialNumber.String(), hex.EncodeToString(cert.AuthorityKeyId), string(resp), ocspExpiry)
				if err != nil {
					log.Critical("Unable to save OCSP response: ", err)
					continue
				}
			}
		}
		ocspRefresh()

		for {
			<-ticker.C
			ocspRefresh()
		}
	}()
	return nil
}
