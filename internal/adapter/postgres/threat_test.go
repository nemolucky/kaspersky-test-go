package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

func TestCreateThreat(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	threat := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Test malware",
		Description: "Integration test",
		Severity:    domain.SeverityHigh,
	}

	created, err := db.CreateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("CreateThreat() error: %v", err)
	}

	if created.MD5 != threat.MD5 {
		t.Errorf(
			"MD5 = %q, want %q",
			created.MD5,
			threat.MD5,
		)
	}

	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	if created.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestCreateThreatDuplicate(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	threat := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Test malware",
		Description: "Integration test",
		Severity:    domain.SeverityHigh,
	}

	created, err := db.CreateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("CreateThreat() error: %v", err)
	}

	if created.MD5 != threat.MD5 {
		t.Errorf(
			"MD5 = %q, want %q",
			created.MD5,
			threat.MD5,
		)
	}

	_, err = db.CreateThreat(ctx, threat)
	if !errors.Is(err, domain.ErrThreatAlreadyExists) {
		t.Fatalf(
			"expected ErrThreatAlreadyExists, got %v",
			err,
		)
	}
}

func TestGetThreatByMD5(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	threat := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Test malware",
		Description: "Integration test",
		Severity:    domain.SeverityHigh,
	}

	created, err := db.CreateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("CreateThreat() error: %v", err)
	}

	if created.MD5 != threat.MD5 {
		t.Errorf(
			"MD5 = %q, want %q",
			created.MD5,
			threat.MD5,
		)
	}

	saved, err := db.GetThreatByMD5(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("GetThreatByMD5() error: %v", err)
	}

	if saved.MD5 != threat.MD5 {
		t.Errorf("MD5 = %q, want %q", saved.MD5, threat.MD5)
	}

	if saved.Name != threat.Name {
		t.Errorf("Name = %q, want %q", saved.Name, threat.Name)
	}

	if saved.Description != threat.Description {
		t.Errorf(
			"Description = %q, want %q",
			saved.Description,
			threat.Description,
		)
	}

	if saved.Severity != threat.Severity {
		t.Errorf(
			"Severity = %q, want %q",
			saved.Severity,
			threat.Severity,
		)
	}

	if saved.CreatedAt.IsZero() || saved.UpdatedAt.IsZero() {
		t.Error("timestamps must not be zero")
	}
}

func TestGetThreatByMD5NotFound(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	md5 := "d41d8cd98f00b204e9800998ecf8427e"

	_, err := db.GetThreatByMD5(ctx, md5)
	if !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf(
			"expected ErrThreatNotFound, got %v",
			err,
		)
	}
}

func TestUpdateThreat(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	threat := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Original malware",
		Description: "Original description",
		Severity:    domain.SeverityLow,
	}

	created, err := db.CreateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("CreateThreat() error: %v", err)
	}

	threat.Name = "Updated malware"
	threat.Description = "Updated description"
	threat.Severity = domain.SeverityCritical

	time.Sleep(10 * time.Millisecond)

	updated, err := db.UpdateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("UpdateThreat() error: %v", err)
	}

	if updated.MD5 != threat.MD5 {
		t.Errorf("MD5 = %q, want %q", updated.MD5, threat.MD5)
	}

	if updated.Name != threat.Name {
		t.Errorf("Name = %q, want %q", updated.Name, threat.Name)
	}

	if updated.Description != threat.Description {
		t.Errorf(
			"Description = %q, want %q",
			updated.Description,
			threat.Description,
		)
	}

	if updated.Severity != threat.Severity {
		t.Errorf(
			"Severity = %q, want %q",
			updated.Severity,
			threat.Severity,
		)
	}

	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf(
			"CreatedAt changed: got %v, want %v",
			updated.CreatedAt,
			created.CreatedAt,
		)
	}

	if !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf(
			"UpdatedAt was not updated: old=%v, new=%v",
			created.UpdatedAt,
			updated.UpdatedAt,
		)
	}

	saved, err := db.GetThreatByMD5(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("GetThreatByMD5() error: %v", err)
	}

	if saved.Name != threat.Name {
		t.Errorf("saved Name = %q, want %q", saved.Name, threat.Name)
	}

	if saved.Description != threat.Description {
		t.Errorf(
			"saved Description = %q, want %q",
			saved.Description,
			threat.Description,
		)
	}

	if saved.Severity != threat.Severity {
		t.Errorf(
			"saved Severity = %q, want %q",
			saved.Severity,
			threat.Severity,
		)
	}

	if !saved.CreatedAt.Equal(created.CreatedAt) {
		t.Error("saved CreatedAt changed")
	}

	if !saved.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Error("saved UpdatedAt does not match updated value")
	}
}

func TestUpdateThreatNotFound(t *testing.T) {
	db := setupTestDB(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	threat := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Nonexistent malware",
		Description: "This threat does not exist",
		Severity:    domain.SeverityHigh,
	}

	updated, err := db.UpdateThreat(ctx, threat)

	if !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf(
			"expected ErrThreatNotFound, got %v",
			err,
		)
	}

	if updated != nil {
		t.Errorf(
			"expected nil threat, got %+v",
			updated,
		)
	}
}
