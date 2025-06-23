package ca

import "net/http"

type Handler struct {
	cert []byte
}

func NewHandler(cert []byte) http.Handler {
	return &Handler{cert: cert}
}

// ca godoc
// @Summary      Gets the CA public certificate
// @Description	 Gets the CA public certificate
// @Produce      plain
// @Success      200
// @Router       /ca [post]
func (ca *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Write(ca.cert)
}
