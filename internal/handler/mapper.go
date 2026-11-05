package handler

import "github.com/nemolucky/kaspersky-test-go/internal/domain"

func toThreatResponse(threat *domain.Threat) ThreatResponse {
	return ThreatResponse{
		MD5:         threat.MD5,
		Name:        threat.Name,
		Description: threat.Description,
		Severity:    string(threat.Severity),
		CreatedAt:   threat.CreatedAt,
		UpdatedAt:   threat.UpdatedAt,
	}
}
