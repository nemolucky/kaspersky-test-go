package domain

import "time"

type Threat struct {
	MD5         string
	Name        string
	Description string
	Severity    Severity
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
