package api

import (
	"encoding/json"
	"net/http"
)

var serverError Error = newApiError("server_error", "There was an unexpected error while handling your request. Please try again later.")

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func newApiError(code string, description string) Error {
	return Error{
		Error:            code,
		ErrorDescription: &description,
	}
}

func writeError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, newApiError(code, description))
}

func writeServerError(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, serverError)
}
