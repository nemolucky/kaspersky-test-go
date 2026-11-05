package handler

import "time"

type ThreatCreateRequest struct {
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ThreatUpdateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ThreatResponse struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details"`
}
