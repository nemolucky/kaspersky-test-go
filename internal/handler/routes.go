package handler

import "net/http"

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /info", h.CreateThreat)
	mux.HandleFunc("GET /info/{md5}", h.GetThreatByMD5)
	mux.HandleFunc("PUT /info/{md5}", h.UpdateThreat)

	return mux
}
