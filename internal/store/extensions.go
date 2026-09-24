package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Extension is a phone account: the number other phones dial and the
// credentials the phone registers with (username = number).
type Extension struct {
	Number  string
	Name    string
	Secret  string
	Enabled bool
	// RequireTLS refuses registrations and calls that aren't over TLS, so
	// the phone's signaling and audio are always encrypted.
	RequireTLS bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

var extNumberRe = regexp.MustCompile(`^[0-9]{2,8}$`)

// ValidateNumber checks that an extension number is 2–8 digits.
func ValidateNumber(n string) error {
	if !extNumberRe.MatchString(n) {
		return fmt.Errorf("extension %q must be 2-8 digits", n)
	}
	return nil
}

func (s *Store) CreateExtension(ctx context.Context, e *Extension) error {
	if err := ValidateNumber(e.Number); err != nil {
		return err
	}
	if e.Secret == "" {
		return errors.New("secret is required")
	}
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO extensions (number, name, secret, enabled, require_tls, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Number, e.Name, e.Secret, e.Enabled, e.RequireTLS, now.Unix(), now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("extension %s: %w", e.Number, ErrExists)
		}
		return err
	}
	e.CreatedAt, e.UpdatedAt = now, now
	return nil
}

func (s *Store) GetExtension(ctx context.Context, number string) (*Extension, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT number, name, secret, enabled, require_tls, created_at, updated_at
		 FROM extensions WHERE number = ?`, number)
	e, err := scanExtension(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("extension %s: %w", number, ErrNotFound)
	}
	return e, err
}

func (s *Store) ListExtensions(ctx context.Context) ([]*Extension, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT number, name, secret, enabled, require_tls, created_at, updated_at
		 FROM extensions ORDER BY length(number), number`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Extension
	for rows.Next() {
		e, err := scanExtension(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateExtension saves Name, Secret, Enabled and RequireTLS for an
// existing extension.
func (s *Store) UpdateExtension(ctx context.Context, e *Extension) error {
	if e.Secret == "" {
		return errors.New("secret is required")
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE extensions SET name = ?, secret = ?, enabled = ?, require_tls = ?, updated_at = ?
		 WHERE number = ?`,
		e.Name, e.Secret, e.Enabled, e.RequireTLS, now.Unix(), e.Number)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("extension %s: %w", e.Number, ErrNotFound)
	}
	e.UpdatedAt = now
	return nil
}

func (s *Store) DeleteExtension(ctx context.Context, number string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM extensions WHERE number = ?`, number)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("extension %s: %w", number, ErrNotFound)
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanExtension(r scanner) (*Extension, error) {
	var e Extension
	var created, updated int64
	if err := r.Scan(&e.Number, &e.Name, &e.Secret, &e.Enabled, &e.RequireTLS, &created, &updated); err != nil {
		return nil, err
	}
	e.CreatedAt, e.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return &e, nil
}

// GenerateSecret returns a 16-character password without look-alike
// characters, since it will often be typed into a phone's keypad or web UI.
func GenerateSecret() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}
