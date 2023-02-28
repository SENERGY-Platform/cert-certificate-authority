package core

import (
	"strconv"
	"time"

	"github.com/SENERGY-Platform/cert-certificate-authority/internal/config"
	"github.com/SENERGY-Platform/cert-certificate-authority/internal/model"

	"github.com/cloudflare/cfssl/certdb"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	cfssl_errors "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
)

func Sign(userName string, signRequest *model.SignRequest, configuration config.Config, db certdb.Accessor) (*[]byte, error) {
	root := universal.Root{
		Config: map[string]string{
			"cert-file": configuration.CACrtPath,
			"key-file":  configuration.PrivateKeyPath,
		},
	}

	// Create the signing policy with the wanted expiration time
	expString := strconv.Itoa(signRequest.Expiration)
	signProfile := cfsslConfig.SigningProfile{
		Usage:        []string{"client auth", "server auth"},
		Expiry:       time.Duration(signRequest.Expiration) * time.Hour,
		ExpiryString: expString + "h",
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
		Hosts:   signRequest.Hostnames,
		Subject: &sub,
		Request: signRequest.Crt,
	}

	cert, err := signMaker.Sign(cfsslSignRequest)
	if err != nil {
		log.Errorf("failed to sign request: %v", err)
		return nil, err
	}

	return &cert, nil
}
