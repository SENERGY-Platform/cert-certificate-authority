package test

import (
	"ca/api/sign"
	"ca/db"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	certsql "github.com/cloudflare/cfssl/certdb/sql"
)

func getTestDB() (acc *certsql.Accessor, err error) {
	db, err := db.GetDB()
	if err != nil {
		log.Printf("ERROR: can not connect to DB: %s", err)
		return
	}
	acc = certsql.NewAccessor(db)
	return
}

func decodeCertificate(certString string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certString))

	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

/*func encodeCertificateRequest(commonName string, hostnames []string) (certString string, err error) {
	csr := x509.CertificateRequest{}

}*/

func createCertificateSigningRequest() {

}

func makeSignRequest(method string, body *string) (*httptest.ResponseRecorder, error) {
	var request *http.Request
	if method == http.MethodPost {
		request = httptest.NewRequest(method, "/sign", strings.NewReader(*body))
	} else {
		request = httptest.NewRequest(method, "/sign", nil)
	}
	responseRecorder := httptest.NewRecorder()

	db, err := getTestDB()
	if err != nil {
		return nil, err
	}

	signHandler := sign.NewHandler(db)

	signHandler.ServeHTTP(responseRecorder, request)
	return responseRecorder, nil
}
