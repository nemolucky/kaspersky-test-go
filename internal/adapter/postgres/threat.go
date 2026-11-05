package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

//go:embed queries/threat/create.sql
var createThreatQuery string

//go:embed queries/threat/update.sql
var updateThreatQuery string

//go:embed queries/threat/get_by_md5.sql
var getThreatByMD5Query string

func (p *Postgres) CreateThreat(
	ctx context.Context,
	threat domain.Threat,
) (*domain.Threat, error) {

	err := p.pool.QueryRow(ctx, createThreatQuery,
		threat.MD5,
		threat.Name,
		threat.Description,
		threat.Severity,
	).Scan(&threat.CreatedAt, &threat.UpdatedAt)

	var pgErr *pgconn.PgError

	if err != nil {
		if errors.As(err, &pgErr) &&
			pgErr.Code == pgerrcode.UniqueViolation {
			return nil, domain.ErrThreatAlreadyExists
		}
		return nil, fmt.Errorf("failed create threat: %w", err)
	}

	return &threat, nil

}

func (p *Postgres) UpdateThreat(
	ctx context.Context,
	threat domain.Threat,
) (*domain.Threat, error) {

	err := p.pool.QueryRow(ctx, updateThreatQuery,
		threat.MD5,
		threat.Name,
		threat.Description,
		threat.Severity,
	).Scan(&threat.CreatedAt, &threat.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrThreatNotFound
		}
		return nil, fmt.Errorf("failed update threat: %w", err)
	}

	return &threat, nil

}

func (p *Postgres) GetThreatByMD5(
	ctx context.Context,
	md5 string,
) (*domain.Threat, error) {

	var threat domain.Threat

	err := p.pool.QueryRow(ctx, getThreatByMD5Query,
		md5,
	).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.Severity,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrThreatNotFound
		}
		return nil, fmt.Errorf("failed get threat: %w", err)
	}

	return &threat, nil

}
