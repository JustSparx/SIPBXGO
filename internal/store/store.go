// Package store is SIPBXGO's persistence layer: a single SQLite file.
//
// The pure-Go modernc.org/sqlite driver keeps the binary cgo-free. WAL mode
// plus a busy timeout lets the CLI (`sipbxgo ext add ...`) write while the
// server is running.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is returned when creating a row whose key is already taken.
var ErrExists = errors.New("already exists")

type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrations are applied in order; the index+1 is stored in PRAGMA user_version.
// Never edit an existing entry once released — append a new one.
var migrations = []string{
	`CREATE TABLE extensions (
		number     TEXT PRIMARY KEY,
		name       TEXT NOT NULL DEFAULT '',
		secret     TEXT NOT NULL,
		enabled    INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE registrations (
		extension   TEXT NOT NULL REFERENCES extensions(number) ON DELETE CASCADE,
		contact     TEXT NOT NULL,
		source      TEXT NOT NULL,
		transport   TEXT NOT NULL,
		user_agent  TEXT NOT NULL DEFAULT '',
		call_id     TEXT NOT NULL DEFAULT '',
		expires_at  INTEGER NOT NULL,
		updated_at  INTEGER NOT NULL,
		PRIMARY KEY (extension, contact)
	);`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
