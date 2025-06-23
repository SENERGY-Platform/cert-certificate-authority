package model

type Revocation struct {
	Serial           string `json:"serial"`
	Authority_key_id string `json:"authority_key_id"`
	Reason           string `json:"reason"`
}

type OCSP struct {
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
}

type SignRequest struct {
	Csr        string   `json:"csr" example:"sd"`
	Expiration string   `json:"expiration" example:"24h"`
	Hostnames  []string `json:"hostnames" example:"localhost"`
}

type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CertificateResult struct {
	Certificate string `json:"certificate"`
}
