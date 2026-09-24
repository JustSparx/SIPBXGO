package store

import (
	"context"
	"time"
)

// Call statuses recorded in call history.
const (
	CallAnswered    = "answered"
	CallBusy        = "busy"
	CallNoAnswer    = "no-answer"
	CallCancelled   = "cancelled"
	CallUnavailable = "unavailable"
	CallFailed      = "failed"
)

// CallRecord is one row of call history (CDR).
type CallRecord struct {
	ID         string
	Caller     string
	Callee     string
	Status     string
	HangupBy   string // caller, callee, or system
	StartedAt  time.Time
	AnsweredAt time.Time // zero if never answered
	EndedAt    time.Time
}

// Talk time, zero for unanswered calls.
func (c *CallRecord) Duration() time.Duration {
	if c.AnsweredAt.IsZero() {
		return 0
	}
	return c.EndedAt.Sub(c.AnsweredAt)
}

func (s *Store) SaveCall(ctx context.Context, c *CallRecord) error {
	var answered int64
	if !c.AnsweredAt.IsZero() {
		answered = c.AnsweredAt.Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO calls (id, caller, callee, status, hangup_by, started_at, answered_at, ended_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Caller, c.Callee, c.Status, c.HangupBy, c.StartedAt.Unix(), answered, c.EndedAt.Unix())
	return err
}

// ListCalls returns calls newest first, optionally only those involving ext
// (ext == "" means all), skipping offset rows.
func (s *Store) ListCalls(ctx context.Context, ext string, limit, offset int) ([]*CallRecord, error) {
	q := `SELECT id, caller, callee, status, hangup_by, started_at, answered_at, ended_at FROM calls`
	var args []any
	if ext != "" {
		q += ` WHERE caller = ? OR callee = ?`
		args = append(args, ext, ext)
	}
	q += ` ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CallRecord
	for rows.Next() {
		var c CallRecord
		var started, answered, ended int64
		if err := rows.Scan(&c.ID, &c.Caller, &c.Callee, &c.Status, &c.HangupBy, &started, &answered, &ended); err != nil {
			return nil, err
		}
		c.StartedAt, c.EndedAt = time.Unix(started, 0), time.Unix(ended, 0)
		if answered > 0 {
			c.AnsweredAt = time.Unix(answered, 0)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}
