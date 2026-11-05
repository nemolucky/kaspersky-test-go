package usecase

import (
	"context"
	"strings"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

type ThreatRepository interface {
	CreateThreat(ctx context.Context, threat domain.Threat) (*domain.Threat, error)
	GetThreatByMD5(ctx context.Context, md5 string) (*domain.Threat, error)
	UpdateThreat(ctx context.Context, threat domain.Threat) (*domain.Threat, error)
}

type ThreatUsecase struct {
	repo ThreatRepository
}

func NewThreatUsecase(repo ThreatRepository) *ThreatUsecase {
	return &ThreatUsecase{repo: repo}
}

func (u *ThreatUsecase) CreateThreat(
	ctx context.Context,
	threat domain.Threat,
) (*domain.Threat, error) {
	md5, err := ParseMD5(threat.MD5)
	if err != nil {
		return nil, err
	}

	threat.MD5 = md5

	if strings.TrimSpace(threat.Name) == "" {
		return nil, domain.ErrInvalidName
	}

	if !threat.Severity.Valid() {
		return nil, domain.ErrInvalidSeverity
	}

	return u.repo.CreateThreat(ctx, threat)
}

func (u *ThreatUsecase) GetThreatByMD5(
	ctx context.Context,
	md5 string,
) (*domain.Threat, error) {
	normalizedMD5, err := ParseMD5(md5)
	if err != nil {
		return nil, err
	}

	return u.repo.GetThreatByMD5(ctx, normalizedMD5)
}

func (u *ThreatUsecase) UpdateThreat(
	ctx context.Context,
	threat domain.Threat,
) (*domain.Threat, error) {
	md5, err := ParseMD5(threat.MD5)
	if err != nil {
		return nil, err
	}

	threat.MD5 = md5

	if strings.TrimSpace(threat.Name) == "" {
		return nil, domain.ErrInvalidName
	}

	if !threat.Severity.Valid() {
		return nil, domain.ErrInvalidSeverity
	}

	return u.repo.UpdateThreat(ctx, threat)
}
