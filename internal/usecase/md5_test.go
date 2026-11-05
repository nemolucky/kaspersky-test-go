package usecase

import (
	"errors"
	"testing"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

func TestParseMD5(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "valid lowercase",
			input: "d41d8cd98f00b204e9800998ecf8427e",
			want:  "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:  "valid uppercase",
			input: "D41D8CD98F00B204E9800998ECF8427E",
			want:  "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:  "valid mixed case",
			input: "D41d8Cd98F00b204E9800998ecF8427E",
			want:  "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "too short",
			input:   "d41d8cd98f00b204e9800998ecf8427",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "too long",
			input:   "d41d8cd98f00b204e9800998ecf8427ee",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "invalid character",
			input:   "z41d8cd98f00b204e9800998ecf8427e",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "leading space",
			input:   " d41d8cd98f00b204e9800998ecf8427e",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "trailing space",
			input:   "d41d8cd98f00b204e9800998ecf8427e ",
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "spaces around",
			input:   " d41d8cd98f00b204e9800998ecf8427e ",
			wantErr: domain.ErrInvalidMD5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMD5(tt.input)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"ParseMD5() error = %v, want %v",
					err,
					tt.wantErr,
				)
			}

			if got != tt.want {
				t.Errorf(
					"ParseMD5() = %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}
