package revoke

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/utils"
	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	stdocsp "golang.org/x/crypto/ocsp"
)

type Handler struct {
	Signer     ocsp.Signer
	dbAccessor certdb.Accessor
	config     config.Config
}

// Copy of cfssl NewOCSPHandler, but with upsert instead of insert of ocsp entries
func NewOCSPHandler(dbAccessor certdb.Accessor, signer ocsp.Signer, config config.Config) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: dbAccessor,
			Signer:     signer,
			config:     config,
		},
		Methods: []string{"POST"},
	}
}

type JsonRevokeRequest struct {
	Serial string `json:"serial"`
	AKI    string `json:"authority_key_id"`
	// See https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1 Use written out code, e.g. "superseded".
	Reason string `json:"reason"`
}

type RevokeWebhookBody struct {
	Username string `json:"username"`
}

// Revoke godoc
// @Summary      Revokes a certificate
// @Description	 Revokes a certificate
// @Accept       json
// @Produce      json
// @Param        payload  body     JsonRevokeRequest     true "Request payload"
// @Success      200
// @Router       /revoke [post]
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Default the status to good so it matches the cli
	var req JsonRevokeRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse revocation request")
	}

	if len(req.Serial) == 0 {
		return errors.NewBadRequestString("serial number is required but not provided")
	}

	var reasonCode int
	reasonCode, err = ocsp.ReasonStringToCode(req.Reason)
	if err != nil {
		return errors.NewBadRequestString("Invalid reason code")
	}

	userId := utils.GetUserId(r)
	certs, err := h.dbAccessor.GetCertificate(req.Serial, req.AKI)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if cert.CommonName.String != userId {
			return errors.NewBadRequestString("Certificate does not belong to you")
		}
		if !cert.RevokedAt.Equal(time.Time{}) {
			return errors.NewBadRequestString("Certificate already revoked")
		}
	}

	err = h.dbAccessor.RevokeCertificate(req.Serial, req.AKI, reasonCode)
	if err != nil {
		return err
	}

	if len(h.config.RevokeWehbook) > 0 {
		go func() {
			content := RevokeWebhookBody{
				Username: userId,
			}
			body, err := json.Marshal(&content)
			if err != nil {
				log.Warningf("Could not marshal RevokeWebhookBody: %v", err)
				return
			}
			resp, err := http.DefaultClient.Post(h.config.RevokeWehbook, "application/json; charset=utf-8", bytes.NewBuffer(body))
			if err != nil {
				log.Warningf("Error invoking revoke webhook: %v", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Warningf("Revoke webhook unable to read response body (Code %v): %v", resp.StatusCode)
				} else {
					log.Warningf("Revoke webhook received non OK response: %v (Code %v)", string(body), resp.StatusCode)
				}
			}
		}()
	}

	if h.Signer != nil {
		// TODO: should these errors be errors?
		// Grab the certificate from the database
		cr, err := h.dbAccessor.GetCertificate(req.Serial, req.AKI)
		if err != nil {
			return err
		}
		if len(cr) != 1 {
			return errors.NewBadRequestString("No unique certificate found")
		}

		cert, err := helpers.ParseCertificatePEM([]byte(cr[0].PEM))
		if err != nil {
			return errors.NewBadRequestString("Unable to parse certificates from PEM data")
		}

		sr := ocsp.SignRequest{
			Certificate: cert,
			Status:      "revoked",
			Reason:      reasonCode,
			RevokedAt:   time.Now().UTC(),
		}

		ocspResponse, err := h.Signer.Sign(sr)
		if err != nil {
			return err
		}

		// We parse the OCSP response in order to get the next
		// update time/expiry time
		ocspParsed, err := stdocsp.ParseResponse(ocspResponse, nil)
		if err != nil {
			return err
		}

		if err = h.dbAccessor.UpsertOCSP(req.Serial, req.AKI, string(ocspResponse), ocspParsed.NextUpdate); err != nil {
			return err
		}
	}
	return nil
}
