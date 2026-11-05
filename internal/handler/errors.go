package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

func mapError(err error) (int, string, string) {
	switch {
	case errors.Is(err, domain.ErrInvalidMD5):
		return http.StatusBadRequest,
			"invalid md5",
			"MD5 must contain 32 hexadecimal characters"

	case errors.Is(err, domain.ErrInvalidName):
		return http.StatusBadRequest,
			"invalid threat name",
			"Name must not be empty"

	case errors.Is(err, domain.ErrInvalidSeverity):
		return http.StatusBadRequest,
			"invalid threat severity",
			"Allowed values: low, medium, high, critical"

	case errors.Is(err, domain.ErrThreatNotFound):
		return http.StatusNotFound,
			"threat not found",
			"No threat exists with the specified MD5"

	case errors.Is(err, domain.ErrThreatAlreadyExists):
		return http.StatusConflict,
			"threat already exists",
			"A threat with the specified MD5 already exists"

	default:
		return http.StatusInternalServerError,
			"internal server error",
			""
	}
}

func renderError(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	err error,
) {
	status, message, details := mapError(err)

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
		Details: details,
	}

	if writeErr := renderJSON(w, status, response); writeErr != nil {
		logger.ErrorContext(
			r.Context(),
			"failed to write error response",
			slog.Any("error", writeErr),
		)
	}
}

func (h *Handler) renderBadRequest(
	w http.ResponseWriter,
	r *http.Request,
	details string,
) {
	if err := renderJSON(w, http.StatusBadRequest, ErrorResponse{
		Details: details,
	}); err != nil {
		h.logger.ErrorContext(
			r.Context(),
			"failed to write bad request response",
			slog.Any("error", err),
		)
	}
}
