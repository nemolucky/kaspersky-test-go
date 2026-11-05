package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func renderJSON(w http.ResponseWriter, status int, data any) error {
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	return nil
}
