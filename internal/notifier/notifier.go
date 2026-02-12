package notifier

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/notifier/pkg/client"
	"github.com/SENERGY-Platform/notifier/pkg/model"
	"github.com/jmoiron/sqlx"
)

func StartNotifier(ctx context.Context, db *sqlx.DB, configuration config.Config) error {
	err := notifyCertificateExpiresSoon(db, configuration)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(24 * time.Hour)

	go func() {
		for {
			select {
			case <-ticker.C:
				err := notifyCertificateExpiresSoon(db, configuration)
				if err != nil {
					fmt.Println("Error notifying about expiring certificates:", err) // TODO: add struct logging
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	return nil
}

func notifyCertificateExpiresSoon(db *sqlx.DB, configuration config.Config) error {
	rows, err := db.Queryx("SELECT serial_number, common_name, expiry FROM certificates WHERE reason = 0 AND expiry > now() AND expiry < now() + '14 days';")
	if err != nil {
		return err
	}
	notifier := client.New(configuration.NotifierUrl)
	var fourteenDaySeconds int64 = 14 * 24 * 60 * 60
	for rows.Next() {
		var serialNumber string
		var commonName string
		var expiry sql.NullTime
		err := rows.Scan(&serialNumber, &commonName, &expiry)
		if err != nil {
			return err
		}
		_, err = notifier.CreateNotification(nil, model.Notification{
			UserId:  commonName,
			Topic:   model.TopicMGW,
			Title:   "Certificate Expiry Warning",
			Message: fmt.Sprintf("Your certificate with serial number %s will expire on %s and has not been renewed.", serialNumber, expiry.Time.Format(time.RFC1123)),
		}, &fourteenDaySeconds)
		if err != nil {
			fmt.Println("Error notifying about expiring certificates:", err) // TODO: add struct logging
		}
	}
	return nil
}
