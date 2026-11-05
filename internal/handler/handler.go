package handler

import (
	"context"
	"log/slog"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

type ThreatUsecase interface {
	CreateThreat(ctx context.Context, threat domain.Threat) (*domain.Threat, error)
	GetThreatByMD5(ctx context.Context, md5 string) (*domain.Threat, error)
	UpdateThreat(ctx context.Context, threat domain.Threat) (*domain.Threat, error)
}

type Handler struct {
	usecase ThreatUsecase
	logger  *slog.Logger
}

func NewHandler(uc ThreatUsecase, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return &Handler{
		usecase: uc,
		logger:  logger,
	}
}
