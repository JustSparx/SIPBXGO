package store

import (
	"context"
	"time"
)

// Registration is one bound contact for an extension. An extension may have
// several (desk phone + softphone); calls will ring all of them.
type Registration struct {
	Extension string
	// Contact is the URI the phone asked to be reached at (often a private IP).
	Contact string
	// Source is the ip:port the REGISTER actually came from. Behind NAT this
	// is the only address that works, so requests are sent here.
	Source    string
	Transport string
	UserAgent string
	CallID    string
	ExpiresAt time.Time
	UpdatedAt time.Time
}

// SaveRegistration inserts or refreshes a binding.
func (s *Store) SaveRegistration(ctx context.Context, r *Registration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO registrations
		   (extension, contact, source, transport, user_agent, call_id, expires_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (extension, contact) DO UPDATE SET
		   source = excluded.source, transport = excluded.transport,
		   user_agent = excluded.user_agent, call_id = excluded.call_id,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		r.Extension, r.Contact, r.Source, r.Transport, r.UserAgent, r.CallID,
		r.ExpiresAt.Unix(), r.UpdatedAt.Unix())
	return err
}

func (s *Store) DeleteRegistration(ctx context.Context, ext, contact string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM registrations WHERE extension = ? AND contact = ?`, ext, contact)
	return err
}

func (s *Store) DeleteRegistrations(ctx context.Context, ext string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM registrations WHERE extension = ?`, ext)
	return err
}

// ListRegistrations returns unexpired bindings, optionally for one extension
// (ext == "" means all).
func (s *Store) ListRegistrations(ctx context.Context, ext string) ([]*Registration, error) {
	q := `SELECT extension, contact, source, transport, user_agent, call_id, expires_at, updated_at
	      FROM registrations WHERE expires_at > ?`
	args := []any{time.Now().Unix()}
	if ext != "" {
		q += ` AND extension = ?`
		args = append(args, ext)
	}
	q += ` ORDER BY extension, updated_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Registration
	for rows.Next() {
		var r Registration
		var exp, upd int64
		if err := rows.Scan(&r.Extension, &r.Contact, &r.Source, &r.Transport,
			&r.UserAgent, &r.CallID, &exp, &upd); err != nil {
			return nil, err
		}
		r.ExpiresAt, r.UpdatedAt = time.Unix(exp, 0), time.Unix(upd, 0)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// PurgeExpiredRegistrations removes stale bindings and reports how many.
func (s *Store) PurgeExpiredRegistrations(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM registrations WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
