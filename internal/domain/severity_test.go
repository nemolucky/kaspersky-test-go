package domain

import "testing"

func TestSeverityValid(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     bool
	}{
		{"low", SeverityLow, true},
		{"medium", SeverityMedium, true},
		{"high", SeverityHigh, true},
		{"critical", SeverityCritical, true},
		{"empty", Severity(""), false},
		{"unknown", Severity("unknown"), false},
		{"uppercase", Severity("HIGH"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.severity.Valid()

			if got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
