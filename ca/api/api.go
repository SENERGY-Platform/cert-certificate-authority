package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/cloudflare/cfssl/errors"
)

type HTTPHandler struct {
	Handler          // CFSSL handler
	Methods []string // The associated HTTP methods
}
type Handler interface {
	Handle(w http.ResponseWriter, r *http.Request) error
}

// ResponseMessage implements the standard for response errors and
// messages. A message has a code and a string message.
type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Response implements the CloudFlare standard for API
// responses.
type Response struct {
	Success  bool              `json:"success"`
	Result   interface{}       `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}

// NewSuccessResponse is a shortcut for creating new successful API
// responses.
func NewSuccessResponse(result interface{}) Response {
	return Response{
		Success:  true,
		Result:   result,
		Errors:   []ResponseMessage{},
		Messages: []ResponseMessage{},
	}
}

// SendResponse builds a response from the result, sets the JSON
// header, and writes to the http.ResponseWriter.
func SendResponse(w http.ResponseWriter, result interface{}) error {
	response := NewSuccessResponse(result)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(response)
	return err
}

// NewErrorResponse is a shortcut for creating an error response for a
// single error.
func NewErrorResponse(message string, code int) Response {
	return Response{
		Success:  false,
		Result:   nil,
		Errors:   []ResponseMessage{{code, message}},
		Messages: []ResponseMessage{},
	}
}

// HandleError is the centralised error handling and reporting.
func HandleError(w http.ResponseWriter, err error) (code int) {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	httpCode := http.StatusInternalServerError

	// If it is recognized as HttpError emitted from cfssl,
	// we rewrite the status code accordingly. If it is a
	// cfssl error, set the http status to StatusBadRequest
	switch err := err.(type) {
	case *errors.HTTPError:
		httpCode = err.StatusCode
		code = err.StatusCode
	case *errors.Error:
		httpCode = http.StatusBadRequest
		code = err.ErrorCode
		msg = err.Message
	}

	response := NewErrorResponse(msg, code)
	jsonMessage, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
	} else {
		msg = string(jsonMessage)
	}
	http.Error(w, msg, httpCode)
	return code
}

// ServeHTTP encapsulates the call to underlying Handler to handle the request
// and return the response with proper HTTP status code
func (h HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var match bool
	// Throw 405 when requested with an unsupported verb.
	for _, m := range h.Methods {
		if m == r.Method {
			match = true
		}
	}
	if match {
		err = h.Handle(w, r)
	} else {
		err = errors.NewMethodNotAllowed(r.Method)
	}
	status := HandleError(w, err)
	log.Printf("%s - \"%s %s\" %d", r.RemoteAddr, r.Method, r.URL, status)
}
