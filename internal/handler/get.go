package handler

import (
	"log/slog"
	"net/http"
)

func (h *Handler) GetThreatByMD5(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	threat, err := h.usecase.GetThreatByMD5(r.Context(), md5)
	if err != nil {
		renderError(w, r, h.logger, err)
		return
	}

	if err := renderJSON(
		w,
		http.StatusOK,
		toThreatResponse(threat),
	); err != nil {
		h.logger.ErrorContext(
			r.Context(),
			"failed to write threat response",
			slog.Any("error", err),
		)
	}
}
