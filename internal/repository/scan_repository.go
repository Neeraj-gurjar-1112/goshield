// Package repository holds the PostgreSQL persistence layer.
package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/neerajgurjar/goshield/internal/model"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("scan not found")

// ScanRepository stores and retrieves scans in PostgreSQL.
type ScanRepository struct {
	pool *pgxpool.Pool
}

// NewScanRepository builds a repository over the given connection pool.
func NewScanRepository(pool *pgxpool.Pool) *ScanRepository {
	return &ScanRepository{pool: pool}
}

const insertScanSQL = `
INSERT INTO scans (
	id, url, normalized_url, domain, protocol, safe,
	risk_score, risk_level, status, reasons, cached, scan_duration_ms, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

// Create persists a scan.
func (r *ScanRepository) Create(ctx context.Context, s *model.Scan) error {
	reasons, err := json.Marshal(s.Reasons)
	if err != nil {
		return fmt.Errorf("marshal reasons: %w", err)
	}

	_, err = r.pool.Exec(ctx, insertScanSQL,
		s.ID, s.URL, s.NormalizedURL, s.Domain, s.Protocol, s.Safe,
		s.RiskScore, string(s.RiskLevel), string(s.Status), reasons,
		s.Cached, s.ScanTimeMs, s.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	return nil
}

const selectScanColumns = `
	id, url, normalized_url, domain, protocol, safe,
	risk_score, risk_level, status, reasons, cached, scan_duration_ms, created_at`

// GetByID returns a single scan, or ErrNotFound when the id does not exist.
func (r *ScanRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Scan, error) {
	row := r.pool.QueryRow(ctx, `SELECT`+selectScanColumns+` FROM scans WHERE id = $1`, id)

	s, err := scanRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("select scan: %w", err)
	}
	return s, nil
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(row rowScanner) (*model.Scan, error) {
	var (
		s         model.Scan
		domain    *string
		protocol  *string
		riskLevel string
		status    string
		reasons   []byte
		duration  *int64
	)

	if err := row.Scan(
		&s.ID, &s.URL, &s.NormalizedURL, &domain, &protocol, &s.Safe,
		&s.RiskScore, &riskLevel, &status, &reasons, &s.Cached, &duration, &s.CreatedAt,
	); err != nil {
		return nil, err
	}

	if domain != nil {
		s.Domain = *domain
	}
	if protocol != nil {
		s.Protocol = *protocol
	}
	if duration != nil {
		s.ScanTimeMs = *duration
	}
	// Postgres hands timestamptz back in the session's zone; the API contract
	// is UTC.
	s.CreatedAt = s.CreatedAt.UTC()
	s.RiskLevel = model.RiskLevel(riskLevel)
	s.Status = model.Status(status)

	s.Reasons = []string{}
	if len(reasons) > 0 {
		if err := json.Unmarshal(reasons, &s.Reasons); err != nil {
			return nil, fmt.Errorf("unmarshal reasons: %w", err)
		}
	}
	return &s, nil
}

// ListFilter narrows and pages a scan listing. Zero values mean "no filter".
type ListFilter struct {
	Page      int
	Limit     int
	RiskLevel string
	Status    string
	Domain    string
	From      *time.Time
	To        *time.Time
}

// offset is the SQL OFFSET implied by the page and limit.
func (f ListFilter) offset() int {
	if f.Page < 1 {
		return 0
	}
	return (f.Page - 1) * f.Limit
}

// List returns a page of scans, newest first, along with the total number of
// rows matching the filter.
func (r *ScanRepository) List(ctx context.Context, f ListFilter) ([]*model.Scan, int, error) {
	where, args := f.buildWhere()

	var total int
	countSQL := `SELECT COUNT(*) FROM scans` + where
	if err := r.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scans: %w", err)
	}
	if total == 0 {
		return []*model.Scan{}, 0, nil
	}

	listSQL := fmt.Sprintf(
		`SELECT%s FROM scans%s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		selectScanColumns, where, len(args)+1, len(args)+2,
	)
	rows, err := r.pool.Query(ctx, listSQL, append(args, f.Limit, f.offset())...)
	if err != nil {
		return nil, 0, fmt.Errorf("select scans: %w", err)
	}
	defer rows.Close()

	scans := make([]*model.Scan, 0, f.Limit)
	for rows.Next() {
		s, err := scanRow(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate scans: %w", err)
	}
	return scans, total, nil
}

// buildWhere assembles the WHERE clause and its arguments from the filter.
// Values are always bound as parameters, never interpolated.
func (f ListFilter) buildWhere() (string, []any) {
	var (
		clauses []string
		args    []any
	)
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if f.RiskLevel != "" {
		add("risk_level = $%d", f.RiskLevel)
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Domain != "" {
		add("domain = $%d", strings.ToLower(f.Domain))
	}
	if f.From != nil {
		add("created_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("created_at <= $%d", *f.To)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
