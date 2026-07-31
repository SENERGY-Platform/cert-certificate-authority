/*
 * Copyright 2026 InfAI (CC SES)
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

package cleanup

import (
	"context"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/jmoiron/sqlx"
)

const cleanupCycle = 24 * time.Hour

// StartCleanup deletes certificates that have been expired for longer than
// configuration.DeleteExpiredCertsAfter, once on startup and then once a day.
func StartCleanup(ctx context.Context, db *sqlx.DB, configuration config.Config) error {
	err := deleteExpiredCertificates(ctx, db, configuration)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(cleanupCycle)

	go func() {
		for {
			select {
			case <-ticker.C:
				err := deleteExpiredCertificates(ctx, db, configuration)
				if err != nil {
					configuration.GetLogger().Error("can not delete expired certificates", "error", err)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	return nil
}

func deleteExpiredCertificates(ctx context.Context, db *sqlx.DB, configuration config.Config) error {
	expiredBefore := time.Now().Add(-configuration.DeleteExpiredCertsAfter)

	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback() // no-op after a successful commit
	}()

	// ocsp_responses references certificates, so those rows have to go first
	_, err = tx.ExecContext(ctx, "DELETE FROM ocsp_responses WHERE (serial_number, authority_key_identifier) IN (SELECT serial_number, authority_key_identifier FROM certificates WHERE expiry IS NOT NULL AND expiry < $1);", expiredBefore)
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, "DELETE FROM certificates WHERE expiry IS NOT NULL AND expiry < $1;", expiredBefore)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	configuration.GetLogger().Info("deleted expired certificates", "count", deleted, "expired_before", expiredBefore)
	return nil
}
