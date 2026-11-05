package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
	"github.com/nemolucky/kaspersky-test-go/internal/handler"
	"github.com/nemolucky/kaspersky-test-go/internal/handler/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newTestHandler(repo *mocks.MockThreatUsecase) http.Handler {
	h := handler.NewHandler(repo, slog.Default())
	return h.Routes()
}

func TestCreateThreat(t *testing.T) {
	createdAt := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Minute)

	threat := domain.Threat{
		MD5:         testMD5,
		Name:        "Test malware",
		Description: "Test description",
		Severity:    domain.SeverityHigh,
	}

	expected := &domain.Threat{
		MD5:         threat.MD5,
		Name:        threat.Name,
		Description: threat.Description,
		Severity:    threat.Severity,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}

	body := `{
		"md5": "d41d8cd98f00b204e9800998ecf8427e",
		"name": "Test malware",
		"description": "Test description",
		"severity": "high"
	}`

	repo := mocks.NewMockThreatUsecase(t)

	repo.EXPECT().
		CreateThreat(mock.Anything, threat).
		Return(expected, nil).
		Once()

	router := newTestHandler(repo)

	req := httptest.NewRequest(
		http.MethodPost,
		"/info",
		bytes.NewBufferString(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response handler.ThreatResponse

	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	require.Equal(t, expected.MD5, response.MD5)
	require.Equal(t, expected.Name, response.Name)
	require.Equal(t, expected.Description, response.Description)
	require.Equal(t, string(expected.Severity), response.Severity)
	require.True(t, expected.CreatedAt.Equal(response.CreatedAt))
	require.True(t, expected.UpdatedAt.Equal(response.UpdatedAt))
}

func TestCreateThreatInvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed json",
			body: `{"md5":`,
		},
		{
			name: "unknown field",
			body: `{
				"md5": "` + testMD5 + `",
				"name": "Test",
				"severity": "high",
				"unknown": "value"
			}`,
		},
		{
			name: "multiple json objects",
			body: `{"md5":"` + testMD5 + `"} {"name":"Test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatUsecase(t)
			router := newTestHandler(repo)

			req := httptest.NewRequest(
				http.MethodPost,
				"/info",
				bytes.NewBufferString(tt.body),
			)

			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code)

			var response handler.ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
			require.NotEmpty(t, response.Message)

			repo.AssertNotCalled(t, "CreateThreat", mock.Anything, mock.Anything)
		})
	}
}

func TestCreateThreatErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantMessage string
		wantDetails string
	}{
		{
			name:        "invalid md5",
			err:         domain.ErrInvalidMD5,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid md5",
			wantDetails: "MD5 must contain 32 hexadecimal characters",
		},
		{
			name:        "invalid name",
			err:         domain.ErrInvalidName,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid threat name",
			wantDetails: "Name must not be empty",
		},
		{
			name:        "invalid severity",
			err:         domain.ErrInvalidSeverity,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid threat severity",
			wantDetails: "Allowed values: low, medium, high, critical",
		},
		{
			name:        "threat already exists",
			err:         domain.ErrThreatAlreadyExists,
			wantStatus:  http.StatusConflict,
			wantMessage: "threat already exists",
			wantDetails: "A threat with the specified MD5 already exists",
		},
		{
			name:        "internal error",
			err:         errors.New("database connection failed"),
			wantStatus:  http.StatusInternalServerError,
			wantMessage: "internal server error",
			wantDetails: "",
		},
	}

	threat := domain.Threat{
		MD5:      testMD5,
		Name:     "Test malware",
		Severity: domain.SeverityHigh,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatUsecase(t)

			repo.EXPECT().
				CreateThreat(mock.Anything, threat).
				Return(nil, tt.err).
				Once()

			router := newTestHandler(repo)

			body, err := json.Marshal(handler.ThreatCreateRequest{
				MD5:      threat.MD5,
				Name:     threat.Name,
				Severity: string(threat.Severity),
			})
			require.NoError(t, err)

			req := httptest.NewRequest(
				http.MethodPost,
				"/info",
				bytes.NewReader(body),
			)

			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)
			require.Equal(
				t,
				"application/json",
				rec.Header().Get("Content-Type"),
			)

			var response handler.ErrorResponse
			require.NoError(
				t,
				json.NewDecoder(rec.Body).Decode(&response),
			)

			require.Equal(t, tt.wantMessage, response.Message)
			require.Equal(t, tt.wantDetails, response.Details)

			if tt.wantStatus == http.StatusInternalServerError {
				require.NotContains(
					t,
					rec.Body.String(),
					"database connection failed",
				)
			}
		})
	}
}

func TestGetThreatByMD5(t *testing.T) {
	repo := mocks.NewMockThreatUsecase(t)

	expected := &domain.Threat{
		MD5:         testMD5,
		Name:        "Test malware",
		Description: "Test description",
		Severity:    domain.SeverityHigh,
		CreatedAt:   time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC),
	}

	repo.EXPECT().
		GetThreatByMD5(mock.Anything, testMD5).
		Return(expected, nil).
		Once()

	router := newTestHandler(repo)

	req := httptest.NewRequest(
		http.MethodGet,
		"/info/"+testMD5,
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response handler.ThreatResponse

	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	require.Equal(t, expected.MD5, response.MD5)
	require.Equal(t, expected.Name, response.Name)
	require.Equal(t, expected.Description, response.Description)
	require.Equal(t, string(expected.Severity), response.Severity)
	require.True(t, expected.CreatedAt.Equal(response.CreatedAt))
	require.True(t, expected.UpdatedAt.Equal(response.UpdatedAt))
}

func TestGetThreatByMD5NotFound(t *testing.T) {
	repo := mocks.NewMockThreatUsecase(t)

	repo.EXPECT().
		GetThreatByMD5(mock.Anything, testMD5).
		Return(nil, domain.ErrThreatNotFound).
		Once()

	router := newTestHandler(repo)

	req := httptest.NewRequest(
		http.MethodGet,
		"/info/"+testMD5,
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)

	var response handler.ErrorResponse

	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)
	require.NotEmpty(t, response.Message)
}

func TestGetThreatByMD5Invalid(t *testing.T) {
	tests := []struct {
		name       string
		md5        string
		wantStatus int
		wantCall   bool
	}{
		{
			name:       "empty md5",
			md5:        "",
			wantStatus: http.StatusNotFound,
			wantCall:   false,
		},
		{
			name:       "short md5",
			md5:        "abc123",
			wantStatus: http.StatusBadRequest,
			wantCall:   true,
		},
		{
			name:       "invalid characters",
			md5:        "z41d8cd98f00b204e9800998ecf8427e",
			wantStatus: http.StatusBadRequest,
			wantCall:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatUsecase(t)

			if tt.wantCall {
				repo.EXPECT().
					GetThreatByMD5(
						mock.Anything,
						tt.md5,
					).
					Return(nil, domain.ErrInvalidMD5).
					Once()
			}

			router := newTestHandler(repo)

			req := httptest.NewRequest(
				http.MethodGet,
				"/info/"+tt.md5,
				nil,
			)

			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantCall {
				var response handler.ErrorResponse

				err := json.NewDecoder(rec.Body).Decode(&response)
				require.NoError(t, err)
				require.NotEmpty(t, response.Message)
			}
		})
	}
}

func TestUpdateThreat(t *testing.T) {
	repo := mocks.NewMockThreatUsecase(t)

	updated := &domain.Threat{
		MD5:         testMD5,
		Name:        "Updated malware",
		Description: "Updated description",
		Severity:    domain.SeverityCritical,
		CreatedAt:   time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC),
	}

	expected := domain.Threat{
		MD5:         testMD5,
		Name:        "Updated malware",
		Description: "Updated description",
		Severity:    domain.SeverityCritical,
	}

	repo.EXPECT().
		UpdateThreat(mock.Anything, expected).
		Return(updated, nil).
		Once()

	router := newTestHandler(repo)

	body := `{
		"name": "Updated malware",
		"description": "Updated description",
		"severity": "critical"
	}`

	req := httptest.NewRequest(
		http.MethodPut,
		"/info/"+testMD5,
		bytes.NewBufferString(body),
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response handler.ThreatResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))

	require.Equal(t, updated.MD5, response.MD5)
	require.Equal(t, updated.Name, response.Name)
	require.Equal(t, updated.Description, response.Description)
	require.Equal(t, string(updated.Severity), response.Severity)
	require.True(t, updated.CreatedAt.Equal(response.CreatedAt))
	require.True(t, updated.UpdatedAt.Equal(response.UpdatedAt))
}

func TestUpdateThreatErrors(t *testing.T) {
	tests := []struct {
		name        string
		md5         string
		body        string
		threat      domain.Threat
		err         error
		wantStatus  int
		wantMessage string
		wantDetails string
		wantCall    bool
	}{
		{
			name: "invalid md5",
			md5:  "invalid",
			body: `{"name":"Test","severity":"high"}`,
			threat: domain.Threat{
				MD5:      "invalid",
				Name:     "Test",
				Severity: domain.SeverityHigh,
			},
			err:         domain.ErrInvalidMD5,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid md5",
			wantDetails: "MD5 must contain 32 hexadecimal characters",
			wantCall:    true,
		},
		{
			name: "invalid name",
			md5:  testMD5,
			body: `{"name":"","severity":"high"}`,
			threat: domain.Threat{
				MD5:      testMD5,
				Name:     "",
				Severity: domain.SeverityHigh,
			},
			err:         domain.ErrInvalidName,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid threat name",
			wantDetails: "Name must not be empty",
			wantCall:    true,
		},
		{
			name: "invalid severity",
			md5:  testMD5,
			body: `{"name":"Test","severity":"unknown"}`,
			threat: domain.Threat{
				MD5:      testMD5,
				Name:     "Test",
				Severity: domain.Severity("unknown"),
			},
			err:         domain.ErrInvalidSeverity,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "invalid threat severity",
			wantDetails: "Allowed values: low, medium, high, critical",
			wantCall:    true,
		},
		{
			name: "threat not found",
			md5:  testMD5,
			body: `{"name":"Test","severity":"high"}`,
			threat: domain.Threat{
				MD5:      testMD5,
				Name:     "Test",
				Severity: domain.SeverityHigh,
			},
			err:         domain.ErrThreatNotFound,
			wantStatus:  http.StatusNotFound,
			wantMessage: "threat not found",
			wantDetails: "No threat exists with the specified MD5",
			wantCall:    true,
		},
		{
			name: "internal error",
			md5:  testMD5,
			body: `{"name":"Test","severity":"high"}`,
			threat: domain.Threat{
				MD5:      testMD5,
				Name:     "Test",
				Severity: domain.SeverityHigh,
			},
			err:         errors.New("database connection failed"),
			wantStatus:  http.StatusInternalServerError,
			wantMessage: "internal server error",
			wantDetails: "",
			wantCall:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatUsecase(t)

			if tt.wantCall {
				repo.EXPECT().
					UpdateThreat(mock.Anything, tt.threat).
					Return(nil, tt.err).
					Once()
			}

			router := newTestHandler(repo)

			req := httptest.NewRequest(
				http.MethodPut,
				"/info/"+tt.md5,
				bytes.NewBufferString(tt.body),
			)

			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)
			require.Equal(
				t,
				"application/json",
				rec.Header().Get("Content-Type"),
			)

			var response handler.ErrorResponse
			require.NoError(
				t,
				json.NewDecoder(rec.Body).Decode(&response),
			)

			require.Equal(t, tt.wantMessage, response.Message)
			require.Equal(t, tt.wantDetails, response.Details)

			if tt.wantStatus == http.StatusInternalServerError {
				require.NotContains(
					t,
					rec.Body.String(),
					"database connection failed",
				)
			}
		})
	}
}

func TestUpdateThreatInvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed json",
			body: `{"name":`,
		},
		{
			name: "unknown field",
			body: `{
				"name": "Test",
				"severity": "high",
				"md5": "another-md5"
			}`,
		},
		{
			name: "multiple json objects",
			body: `{"name":"Test","severity":"high"} {"name":"Other"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockThreatUsecase(t)
			router := newTestHandler(repo)

			req := httptest.NewRequest(
				http.MethodPut,
				"/info/"+testMD5,
				bytes.NewBufferString(tt.body),
			)

			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code)

			var response handler.ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
			require.NotEmpty(t, response.Message)

			repo.AssertNotCalled(
				t,
				"UpdateThreat",
				mock.Anything,
				mock.Anything,
			)
		})
	}
}
