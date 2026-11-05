package usecase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
	"github.com/nemolucky/kaspersky-test-go/internal/usecase"
	"github.com/nemolucky/kaspersky-test-go/internal/usecase/mocks"
	"github.com/stretchr/testify/require"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func TestCreateThreat(t *testing.T) {
	ctx := context.Background()
	repo := mocks.NewMockThreatRepository(t)

	threat := domain.Threat{
		MD5:         testMD5,
		Name:        "Test malware",
		Description: "Test description",
		Severity:    domain.SeverityHigh,
	}

	repo.EXPECT().
		CreateThreat(ctx, threat).
		Return(&threat, nil).
		Once()

	uc := usecase.NewThreatUsecase(repo)

	got, err := uc.CreateThreat(ctx, threat)

	require.NoError(t, err)
	require.Equal(t, &threat, got)
}

func TestCreateThreatInvalidSeverity(t *testing.T) {
	ctx := context.Background()
	repo := mocks.NewMockThreatRepository(t)

	threat := domain.Threat{
		MD5:      testMD5,
		Name:     "Test malware",
		Severity: domain.Severity("unknown"),
	}

	uc := usecase.NewThreatUsecase(repo)

	got, err := uc.CreateThreat(ctx, threat)

	require.ErrorIs(t, err, domain.ErrInvalidSeverity)
	require.Nil(t, got)

	repo.AssertNotCalled(t, "CreateThreat")
}

func TestGetThreatByMD5(t *testing.T) {
	ctx := context.Background()
	repo := mocks.NewMockThreatRepository(t)

	expected := &domain.Threat{
		MD5:      testMD5,
		Name:     "Test malware",
		Severity: domain.SeverityHigh,
	}

	repo.EXPECT().
		GetThreatByMD5(ctx, testMD5).
		Return(expected, nil).
		Once()

	uc := usecase.NewThreatUsecase(repo)

	got, err := uc.GetThreatByMD5(
		ctx,
		"D41D8CD98F00B204E9800998ECF8427E",
	)

	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestUpdateThreat(t *testing.T) {
	ctx := context.Background()
	repo := mocks.NewMockThreatRepository(t)

	threat := domain.Threat{
		MD5:         testMD5,
		Name:        "Updated malware",
		Description: "Updated description",
		Severity:    domain.SeverityCritical,
	}

	repo.EXPECT().
		UpdateThreat(ctx, threat).
		Return(&threat, nil).
		Once()

	uc := usecase.NewThreatUsecase(repo)

	got, err := uc.UpdateThreat(ctx, threat)

	require.NoError(t, err)
	require.Equal(t, &threat, got)
}

func TestCreateThreatValidation(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*domain.Threat)
		wantErr error
	}{
		{
			name: "invalid md5",
			change: func(threat *domain.Threat) {
				threat.MD5 = "invalid"
			},
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name: "empty name",
			change: func(threat *domain.Threat) {
				threat.Name = ""
			},
			wantErr: domain.ErrInvalidName,
		},
		{
			name: "whitespace name",
			change: func(threat *domain.Threat) {
				threat.Name = "   "
			},
			wantErr: domain.ErrInvalidName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatRepository(t)
			uc := usecase.NewThreatUsecase(repo)

			threat := domain.Threat{
				MD5:      testMD5,
				Name:     "Test malware",
				Severity: domain.SeverityHigh,
			}

			tt.change(&threat)

			got, err := uc.CreateThreat(
				context.Background(),
				threat,
			)

			require.ErrorIs(t, err, tt.wantErr)
			require.Nil(t, got)
			repo.AssertNotCalled(t, "CreateThreat")
		})
	}
}

func TestUpdateThreatValidation(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*domain.Threat)
		wantErr error
	}{
		{
			name: "invalid md5",
			change: func(threat *domain.Threat) {
				threat.MD5 = "invalid"
			},
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name: "empty name",
			change: func(threat *domain.Threat) {
				threat.Name = ""
			},
			wantErr: domain.ErrInvalidName,
		},
		{
			name: "whitespace name",
			change: func(threat *domain.Threat) {
				threat.Name = "   "
			},
			wantErr: domain.ErrInvalidName,
		},
		{
			name: "invalid severity",
			change: func(threat *domain.Threat) {
				threat.Severity = domain.Severity("unknown")
			},
			wantErr: domain.ErrInvalidSeverity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatRepository(t)
			uc := usecase.NewThreatUsecase(repo)

			threat := domain.Threat{
				MD5:      testMD5,
				Name:     "Test malware",
				Severity: domain.SeverityHigh,
			}

			tt.change(&threat)

			got, err := uc.UpdateThreat(
				context.Background(),
				threat,
			)

			require.ErrorIs(t, err, tt.wantErr)
			require.Nil(t, got)
			repo.AssertNotCalled(t, "UpdateThreat")
		})
	}
}

func TestGetThreatByMD5Invalid(t *testing.T) {
	tests := []struct {
		name string
		md5  string
	}{
		{
			name: "empty md5",
			md5:  "",
		},
		{
			name: "short md5",
			md5:  "abc123",
		},
		{
			name: "invalid characters",
			md5:  "z41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name: "md5 with spaces",
			md5:  " " + testMD5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatRepository(t)
			uc := usecase.NewThreatUsecase(repo)

			got, err := uc.GetThreatByMD5(
				context.Background(),
				tt.md5,
			)

			require.ErrorIs(t, err, domain.ErrInvalidMD5)
			require.Nil(t, got)
			repo.AssertNotCalled(t, "GetThreatByMD5")
		})
	}
}

func TestCreateThreatRepositoryError(t *testing.T) {
	tests := []struct {
		name    string
		repoErr error
	}{
		{
			name:    "already exists",
			repoErr: domain.ErrThreatAlreadyExists,
		},
		{
			name:    "database error",
			repoErr: errors.New("database unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := mocks.NewMockThreatRepository(t)

			threat := domain.Threat{
				MD5:      testMD5,
				Name:     "Test malware",
				Severity: domain.SeverityHigh,
			}

			repo.EXPECT().
				CreateThreat(ctx, threat).
				Return(nil, tt.repoErr).
				Once()

			uc := usecase.NewThreatUsecase(repo)

			got, err := uc.CreateThreat(ctx, threat)

			require.ErrorIs(t, err, tt.repoErr)
			require.Nil(t, got)
		})
	}
}

func TestGetThreatByMD5RepositoryError(t *testing.T) {
	tests := []struct {
		name    string
		repoErr error
	}{
		{
			name:    "not found",
			repoErr: domain.ErrThreatNotFound,
		},
		{
			name:    "database error",
			repoErr: errors.New("database unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := mocks.NewMockThreatRepository(t)

			repo.EXPECT().
				GetThreatByMD5(ctx, testMD5).
				Return(nil, tt.repoErr).
				Once()

			uc := usecase.NewThreatUsecase(repo)

			got, err := uc.GetThreatByMD5(ctx, testMD5)

			require.ErrorIs(t, err, tt.repoErr)
			require.Nil(t, got)
		})
	}
}

func TestUpdateThreatRepositoryError(t *testing.T) {
	tests := []struct {
		name    string
		repoErr error
	}{
		{
			name:    "not found",
			repoErr: domain.ErrThreatNotFound,
		},
		{
			name:    "database error",
			repoErr: errors.New("database unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := mocks.NewMockThreatRepository(t)

			threat := domain.Threat{
				MD5:      testMD5,
				Name:     "Updated malware",
				Severity: domain.SeverityCritical,
			}

			repo.EXPECT().
				UpdateThreat(ctx, threat).
				Return(nil, tt.repoErr).
				Once()

			uc := usecase.NewThreatUsecase(repo)

			got, err := uc.UpdateThreat(ctx, threat)

			require.ErrorIs(t, err, tt.repoErr)
			require.Nil(t, got)
		})
	}
}

func TestUpdateThreatNormalizeMD5(t *testing.T) {
	ctx := context.Background()
	repo := mocks.NewMockThreatRepository(t)

	threat := domain.Threat{
		MD5:      "D41D8CD98F00B204E9800998ECF8427E",
		Name:     "Updated malware",
		Severity: domain.SeverityHigh,
	}

	expected := threat
	expected.MD5 = testMD5

	repo.EXPECT().
		UpdateThreat(ctx, expected).
		Return(&expected, nil).
		Once()

	uc := usecase.NewThreatUsecase(repo)

	got, err := uc.UpdateThreat(ctx, threat)

	require.NoError(t, err)
	require.Equal(t, &expected, got)
}
