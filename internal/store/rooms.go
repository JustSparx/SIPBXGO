package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Room is a conference room: dialing its number joins it.
type Room struct {
	Number    string
	Name      string
	PIN       string // digits; empty means no PIN
	CreatedAt time.Time
}

var pinRe = regexp.MustCompile(`^[0-9]{0,12}$`)

// ErrNumberTaken is returned when a room or extension number is already
// used by the other kind.
var ErrNumberTaken = errors.New("number is already used")

func (s *Store) numberUsed(ctx context.Context, number string) (string, error) {
	var kind string
	err := s.db.QueryRowContext(ctx,
		`SELECT 'an extension' FROM extensions WHERE number = ?
		 UNION ALL SELECT 'a conference room' FROM rooms WHERE number = ?`, number, number).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return kind, err
}

func (s *Store) CreateRoom(ctx context.Context, r *Room) error {
	if err := ValidateNumber(r.Number); err != nil {
		return err
	}
	if !pinRe.MatchString(r.PIN) {
		return errors.New("PIN must be up to 12 digits")
	}
	kind, err := s.numberUsed(ctx, r.Number)
	if err != nil {
		return err
	}
	if kind != "" {
		return fmt.Errorf("%s is already %s: %w", r.Number, kind, ErrNumberTaken)
	}
	now := time.Now()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO rooms (number, name, pin, created_at) VALUES (?, ?, ?, ?)`,
		r.Number, r.Name, r.PIN, now.Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("room %s: %w", r.Number, ErrExists)
	}
	r.CreatedAt = now
	return err
}

func (s *Store) GetRoom(ctx context.Context, number string) (*Room, error) {
	var r Room
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT number, name, pin, created_at FROM rooms WHERE number = ?`, number).
		Scan(&r.Number, &r.Name, &r.PIN, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("room %s: %w", number, ErrNotFound)
	}
	r.CreatedAt = time.Unix(created, 0)
	return &r, err
}

func (s *Store) ListRooms(ctx context.Context) ([]*Room, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT number, name, pin, created_at FROM rooms ORDER BY length(number), number`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Room
	for rows.Next() {
		var r Room
		var created int64
		if err := rows.Scan(&r.Number, &r.Name, &r.PIN, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(created, 0)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// UpdateRoom saves Name and PIN.
func (s *Store) UpdateRoom(ctx context.Context, r *Room) error {
	if !pinRe.MatchString(r.PIN) {
		return errors.New("PIN must be up to 12 digits")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE rooms SET name = ?, pin = ? WHERE number = ?`, r.Name, r.PIN, r.Number)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("room %s: %w", r.Number, ErrNotFound)
	}
	return nil
}

func (s *Store) DeleteRoom(ctx context.Context, number string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rooms WHERE number = ?`, number)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("room %s: %w", number, ErrNotFound)
	}
	return nil
}
