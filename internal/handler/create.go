package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req ThreatCreateRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		renderBadRequest(w, "invalid request body")
		return
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		renderBadRequest(w, "request body must contain a single JSON object")
		return
	}

	threat := domain.Threat{
		MD5:         req.MD5,
		Name:        req.Name,
		Description: req.Description,
		Severity:    domain.Severity(req.Severity),
	}

	created, err := h.usecase.CreateThreat(r.Context(), threat)
	if err != nil {
		renderError(w, r, h.logger, err)
		return
	}

	if err := renderJSON(w, http.StatusCreated, toThreatResponse(created)); err != nil {
		h.logger.ErrorContext(
			r.Context(),
			"failed to write threat response",
			slog.Any("error", err),
		)
	}
}
