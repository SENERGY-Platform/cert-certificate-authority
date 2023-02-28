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
	Crt        string   `json:"crt" example:"sd"`
	Expiration int      `json:"expiration" example:"24"`
	Hostnames  []string `json:"hostnames" example:"localhost"`
}

type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CertificateResult struct {
	Certificate string `json:"certificate"`
}

type Response struct {
	Success  bool              `json:"success"`
	Result   CertificateResult `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}

type OCSPResult struct {
	OCSPResponse string `json:"ocspResponse"`
}

type OCSPResponse struct {
	Success  bool              `json:"success"`
	Result   OCSPResult        `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}
