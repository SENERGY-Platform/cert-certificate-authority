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

package list

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/utils"
	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/errors"

	"github.com/jmoiron/sqlx"
)

type Handler struct {
	db *sqlx.DB
}

func NewHandler(db *sqlx.DB) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			db: db,
		},
		Methods: []string{"GET"},
	}
}

type CertificateInfo struct {
	SerialNumber           string    `json:"serial_number" db:"serial_number"`
	AuthorityKeyIdentifier string    `json:"authority_key_identifier" db:"authority_key_identifier"`
	SANs                   []string  `json:"sans" db:"-"`
	SANsUint               []byte    `json:"-" db:"sans"`
	IssuedAt               time.Time `json:"issued_at" db:"issued_at"`
	NotBefore              time.Time `json:"not_before" db:"not_before"`
	Expiry                 time.Time `json:"expiry" db:"expiry"`
	RevokedAt              time.Time `json:"revoked_at" db:"revoked_at"`
	Reason                 int       `json:"reason" db:"reason"`
}

// List godoc
// @Summary      Lists all certificates of the user
// @Description	 Lists all certificates of the user
// @Accept       json
// @Produce      json
// @Success      200 {array} CertificateInfo
// @Router       /list [get]
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	resp := []CertificateInfo{}
	userId := utils.GetUserId(r)
	rows, err := h.db.Queryx(fmt.Sprintf("SELECT serial_number, authority_key_identifier, sans, issued_at, not_before, expiry, revoked_at, reason FROM certificates WHERE common_name = '%s';", userId))
	if err != nil {
		return &errors.Error{
			ErrorCode: http.StatusInternalServerError,
			Message:   err.Error(),
		}
	}
	for rows.Next() {
		info := CertificateInfo{}
		err = rows.StructScan(&info)
		if err != nil {
			return &errors.Error{
				ErrorCode: http.StatusInternalServerError,
				Message:   err.Error(),
			}
		}
		err = json.Unmarshal(info.SANsUint, &info.SANs)
		if err != nil {
			return &errors.Error{
				ErrorCode: http.StatusInternalServerError,
				Message:   err.Error(),
			}
		}
		resp = append(resp, info)
	}
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		return &errors.Error{
			ErrorCode: http.StatusInternalServerError,
			Message:   err.Error(),
		}
	}
	return nil
}
