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
