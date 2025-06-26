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
