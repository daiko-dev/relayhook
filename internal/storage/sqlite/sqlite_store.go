package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
	_ "modernc.org/sqlite"
)

var _ domain.Store = (*SQLiteStore)(nil)

type SQLiteStore struct {
	db *sql.DB
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS apps (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
	id TEXT PRIMARY KEY,
	app_id TEXT NOT NULL,
	url TEXT NOT NULL,
	secret TEXT NOT NULL,
	event_types TEXT NOT NULL,
	is_active INTEGER NOT NULL DEFAULT 1,
	max_retries INTEGER NOT NULL DEFAULT 5,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_app_id ON endpoints(app_id);

CREATE TABLE IF NOT EXISTS events (
	id TEXT PRIMARY KEY,
	app_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	payload TEXT NOT NULL,
	idempotency_key TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_app_idempotency
	ON events(app_id, idempotency_key)
	WHERE idempotency_key != '';

CREATE TABLE IF NOT EXISTS deliveries (
	id TEXT PRIMARY KEY,
	event_id TEXT NOT NULL,
	endpoint_id TEXT NOT NULL,
	status TEXT NOT NULL,
	attempt_count INTEGER NOT NULL DEFAULT 0,
	max_retries INTEGER NOT NULL DEFAULT 5,
	status_code INTEGER NOT NULL DEFAULT 0,
	response_time_ms INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	next_retry_at TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_status ON deliveries(status);
CREATE INDEX IF NOT EXISTS idx_deliveries_endpoint_id ON deliveries(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_event_id ON deliveries(event_id);
`

func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		dsn = ":memory:"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Single connection keeps :memory: alive and prevents intra-process SQLITE_BUSY lock upgrade deadlocks.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA synchronous=NORMAL;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("exec %s: %w", p, err)
		}
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	now := formatTime(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO apps (id, name, created_at) VALUES (?, ?, ?)`,
		domain.DefaultAppID, "Default App", now,
	); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("seed default app: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) CreateApp(ctx context.Context, app *domain.App) error {
	if app == nil || strings.TrimSpace(app.ID) == "" || strings.TrimSpace(app.Name) == "" {
		return domain.ErrInvalidInput
	}
	createdAt := app.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO apps (id, name, created_at) VALUES (?, ?, ?)`,
		app.ID, app.Name, formatTime(createdAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return domain.ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *SQLiteStore) GetApp(ctx context.Context, id string) (*domain.App, error) {
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}
	var a domain.App
	var createdStr string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, name, created_at FROM apps WHERE id = ?`,
		id,
	).Scan(&a.ID, &a.Name, &createdStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	a.CreatedAt, _ = parseTime(createdStr)
	return &a, nil
}

func (s *SQLiteStore) ListApps(ctx context.Context) ([]*domain.App, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM apps ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apps := make([]*domain.App, 0)
	for rows.Next() {
		var a domain.App
		var createdStr string
		if err := rows.Scan(&a.ID, &a.Name, &createdStr); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = parseTime(createdStr)
		apps = append(apps, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return apps, nil
}

func (s *SQLiteStore) CreateEndpoint(ctx context.Context, ep *domain.Endpoint) error {
	if ep == nil || strings.TrimSpace(ep.ID) == "" || strings.TrimSpace(ep.URL) == "" {
		return domain.ErrInvalidInput
	}
	appID := ep.AppID
	if strings.TrimSpace(appID) == "" {
		appID = domain.DefaultAppID
	}
	maxRetries := ep.MaxRetries
	if maxRetries <= 0 {
		maxRetries = domain.DefaultMaxRetries
	}
	createdAt := ep.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	eventTypes := ep.EventTypes
	if eventTypes == nil {
		eventTypes = []string{}
	}
	evTypesJSON, err := json.Marshal(eventTypes)
	if err != nil {
		return fmt.Errorf("marshal event_types: %w", err)
	}
	isActive := 0
	if ep.IsActive {
		isActive = 1
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO endpoints (id, app_id, url, secret, event_types, is_active, max_retries, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.ID, appID, ep.URL, ep.Secret, string(evTypesJSON), isActive, maxRetries, formatTime(createdAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return domain.ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *SQLiteStore) GetEndpoint(ctx context.Context, id string) (*domain.Endpoint, error) {
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, app_id, url, secret, event_types, is_active, max_retries, created_at
		 FROM endpoints WHERE id = ?`,
		id,
	)
	return scanEndpoint(row)
}

func (s *SQLiteStore) ListEndpoints(ctx context.Context, appID string) ([]*domain.Endpoint, error) {
	var (
		rows *sql.Rows
		err  error
	)
	filterAppID := strings.TrimSpace(appID)
	if filterAppID == "" {
		rows, err = s.db.QueryContext(
			ctx,
			`SELECT id, app_id, url, secret, event_types, is_active, max_retries, created_at
			 FROM endpoints ORDER BY created_at ASC, id ASC`,
		)
	} else {
		rows, err = s.db.QueryContext(
			ctx,
			`SELECT id, app_id, url, secret, event_types, is_active, max_retries, created_at
			 FROM endpoints WHERE app_id = ? ORDER BY created_at ASC, id ASC`,
			filterAppID,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]*domain.Endpoint, 0)
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func (s *SQLiteStore) DeleteEndpoint(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return domain.ErrInvalidInput
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM endpoints WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) CreateEvent(ctx context.Context, ev *domain.Event) (*domain.Event, bool, error) {
	if ev == nil || strings.TrimSpace(ev.ID) == "" || strings.TrimSpace(ev.EventType) == "" {
		return nil, false, domain.ErrInvalidInput
	}
	if len(ev.Payload) > 0 && !json.Valid(ev.Payload) {
		return nil, false, domain.ErrInvalidInput
	}

	e := *ev
	if strings.TrimSpace(e.AppID) == "" {
		e.AppID = domain.DefaultAppID
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	} else {
		e.CreatedAt = e.CreatedAt.UTC()
	}
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage("{}")
	} else {
		e.Payload = append(json.RawMessage(nil), ev.Payload...)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if e.IdempotencyKey != "" {
		existing, err := getEventByIdempotencyKeyTx(ctx, tx, e.AppID, e.IdempotencyKey)
		if err == nil {
			return existing, false, nil
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, false, err
		}
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO events (id, app_id, event_type, payload, idempotency_key, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, e.AppID, e.EventType, string(e.Payload), e.IdempotencyKey, formatTime(e.CreatedAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			if e.IdempotencyKey != "" {
				existing, lookupErr := getEventByIdempotencyKeyTx(ctx, tx, e.AppID, e.IdempotencyKey)
				if lookupErr == nil {
					return existing, false, nil
				}
			}
			return nil, false, domain.ErrDuplicate
		}
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &e, true, nil
}

func (s *SQLiteStore) GetEvent(ctx context.Context, id string) (*domain.Event, error) {
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, app_id, event_type, payload, idempotency_key, created_at FROM events WHERE id = ?`,
		id,
	)
	return scanEvent(row)
}

func (s *SQLiteStore) CreateDelivery(ctx context.Context, d *domain.DeliveryAttempt) error {
	if d == nil || strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.EventID) == "" || strings.TrimSpace(d.EndpointID) == "" {
		return domain.ErrInvalidInput
	}
	status := d.Status
	if status == "" {
		status = domain.StatusQueued
	}
	maxRetries := d.MaxRetries
	if maxRetries <= 0 {
		maxRetries = domain.DefaultMaxRetries
	}
	now := time.Now().UTC()
	createdAt := d.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := d.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}

	var nextRetry sql.NullString
	if d.NextRetryAt != nil && !d.NextRetryAt.IsZero() {
		nextRetry = sql.NullString{String: formatTime(*d.NextRetryAt), Valid: true}
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO deliveries (
			id, event_id, endpoint_id, status, attempt_count, max_retries,
			status_code, response_time_ms, last_error, next_retry_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.EventID, d.EndpointID, string(status), d.AttemptCount, maxRetries,
		d.StatusCode, d.ResponseTime, d.LastError, nextRetry, formatTime(createdAt), formatTime(updatedAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return domain.ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *SQLiteStore) GetDelivery(ctx context.Context, id string) (*domain.DeliveryAttempt, error) {
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, event_id, endpoint_id, status, attempt_count, max_retries,
		        status_code, response_time_ms, last_error, next_retry_at, created_at, updated_at
		 FROM deliveries WHERE id = ?`,
		id,
	)
	return scanDelivery(row)
}

func (s *SQLiteStore) UpdateDelivery(ctx context.Context, d *domain.DeliveryAttempt) error {
	if d == nil || strings.TrimSpace(d.ID) == "" {
		return domain.ErrInvalidInput
	}
	updatedAt := d.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	var nextRetry sql.NullString
	if d.NextRetryAt != nil && !d.NextRetryAt.IsZero() {
		nextRetry = sql.NullString{String: formatTime(*d.NextRetryAt), Valid: true}
	}

	res, err := s.db.ExecContext(
		ctx,
		`UPDATE deliveries
		 SET event_id = COALESCE(NULLIF(?, ''), event_id),
		     endpoint_id = COALESCE(NULLIF(?, ''), endpoint_id),
		     status = ?,
		     attempt_count = ?,
		     max_retries = CASE WHEN ? <= 0 THEN max_retries ELSE ? END,
		     status_code = ?,
		     response_time_ms = ?,
		     last_error = ?,
		     next_retry_at = ?,
		     updated_at = ?
		 WHERE id = ?`,
		strings.TrimSpace(d.EventID),
		strings.TrimSpace(d.EndpointID),
		string(d.Status),
		d.AttemptCount,
		d.MaxRetries, d.MaxRetries,
		d.StatusCode,
		d.ResponseTime,
		d.LastError,
		nextRetry,
		formatTime(updatedAt),
		d.ID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) ListDeliveries(ctx context.Context, filter domain.DeliveryFilter) ([]*domain.DeliveryAttempt, error) {
	query := `SELECT id, event_id, endpoint_id, status, attempt_count, max_retries,
	                 status_code, response_time_ms, last_error, next_retry_at, created_at, updated_at
	          FROM deliveries WHERE 1=1`
	var args []any

	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, string(filter.Status))
	}
	if filter.EndpointID != "" {
		query += ` AND endpoint_id = ?`
		args = append(args, filter.EndpointID)
	}
	if filter.EventID != "" {
		query += ` AND event_id = ?`
		args = append(args, filter.EventID)
	}
	query += ` ORDER BY created_at ASC, id ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	deliveries := make([]*domain.DeliveryAttempt, 0)
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return deliveries, nil
}

func (s *SQLiteStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store not initialized")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(scanner rowScanner) (*domain.Endpoint, error) {
	var (
		ep          domain.Endpoint
		evTypesJSON string
		isActive    int
		createdStr  string
	)
	if err := scanner.Scan(
		&ep.ID, &ep.AppID, &ep.URL, &ep.Secret,
		&evTypesJSON, &isActive, &ep.MaxRetries, &createdStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	ep.IsActive = isActive != 0
	ep.CreatedAt, _ = parseTime(createdStr)
	if evTypesJSON != "" {
		if err := json.Unmarshal([]byte(evTypesJSON), &ep.EventTypes); err != nil {
			return nil, fmt.Errorf("unmarshal event_types: %w", err)
		}
	}
	if ep.EventTypes == nil {
		ep.EventTypes = []string{}
	}
	return &ep, nil
}

func scanEvent(scanner rowScanner) (*domain.Event, error) {
	var (
		ev         domain.Event
		payloadStr string
		createdStr string
	)
	if err := scanner.Scan(
		&ev.ID, &ev.AppID, &ev.EventType, &payloadStr, &ev.IdempotencyKey, &createdStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	ev.Payload = json.RawMessage(payloadStr)
	ev.CreatedAt, _ = parseTime(createdStr)
	return &ev, nil
}

func getEventByIdempotencyKeyTx(ctx context.Context, tx *sql.Tx, appID, idempotencyKey string) (*domain.Event, error) {
	row := tx.QueryRowContext(
		ctx,
		`SELECT id, app_id, event_type, payload, idempotency_key, created_at
		 FROM events WHERE app_id = ? AND idempotency_key = ?`,
		appID, idempotencyKey,
	)
	return scanEvent(row)
}

func scanDelivery(scanner rowScanner) (*domain.DeliveryAttempt, error) {
	var (
		d          domain.DeliveryAttempt
		statusStr  string
		nextRetry  sql.NullString
		createdStr string
		updatedStr string
	)
	if err := scanner.Scan(
		&d.ID, &d.EventID, &d.EndpointID, &statusStr, &d.AttemptCount, &d.MaxRetries,
		&d.StatusCode, &d.ResponseTime, &d.LastError, &nextRetry, &createdStr, &updatedStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	d.Status = domain.DeliveryStatus(statusStr)
	d.CreatedAt, _ = parseTime(createdStr)
	d.UpdatedAt, _ = parseTime(updatedStr)
	if nextRetry.Valid && nextRetry.String != "" {
		if t, err := parseTime(nextRetry.String); err == nil {
			d.NextRetryAt = &t
		}
	}
	return &d, nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") ||
		strings.Contains(msg, "primary key constraint failed")
}
