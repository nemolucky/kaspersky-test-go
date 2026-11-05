package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

func mapError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrInvalidMD5):
		return http.StatusBadRequest, "invalid md5"

	case errors.Is(err, domain.ErrInvalidName):
		return http.StatusBadRequest, "invalid threat name"

	case errors.Is(err, domain.ErrInvalidSeverity):
		return http.StatusBadRequest, "invalid threat severity"

	case errors.Is(err, domain.ErrThreatNotFound):
		return http.StatusNotFound, "threat not found"

	case errors.Is(err, domain.ErrThreatAlreadyExists):
		return http.StatusConflict, "threat already exists"

	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

func renderError(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	err error,
) {
	status, message := mapError(err)

	if status >= http.StatusInternalServerError {
		logger.ErrorContext(
			r.Context(),
			"request failed",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Any("error", err),
		)
	}

	response := ErrorResponse{
		Message: message,
	}

	if writeErr := renderJSON(w, status, response); writeErr != nil {
		logger.ErrorContext(
			r.Context(),
			"failed to write error response",
			slog.Any("error", writeErr),
		)
	}
}

func renderBadRequest(w http.ResponseWriter, message string) {
	_ = renderJSON(w, http.StatusBadRequest, ErrorResponse{
		Message: message,
		Details: "",
	})
}
