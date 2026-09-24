package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Admin is a web UI login.
type Admin struct {
	Username  string
	CreatedAt time.Time
}

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// MinPasswordLen is the shortest admin password accepted.
const MinPasswordLen = 10

var ErrBadLogin = errors.New("wrong username or password")

func validatePassword(p string) error {
	if len(p) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(p) > 72 { // bcrypt's limit
		return errors.New("password must be at most 72 characters")
	}
	return nil
}

func (s *Store) CreateAdmin(ctx context.Context, username, password string) error {
	if !usernameRe.MatchString(username) {
		return fmt.Errorf("username %q: use 1-32 letters, digits, . _ -", username)
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, string(hash), time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("admin %s: %w", username, ErrExists)
	}
	return err
}

// SetAdminPassword changes a password and signs out that admin's sessions.
func (s *Store) SetAdminPassword(ctx context.Context, username, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET password_hash = ? WHERE username = ?`, string(hash), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("admin %s: %w", username, ErrNotFound)
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username)
	return err
}

func (s *Store) DeleteAdmin(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admins WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("admin %s: %w", username, ErrNotFound)
	}
	return nil
}

func (s *Store) ListAdmins(ctx context.Context) ([]*Admin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, created_at FROM admins ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Admin
	for rows.Next() {
		var a Admin
		var created int64
		if err := rows.Scan(&a.Username, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(created, 0)
		out = append(out, &a)
	}
	return out, rows.Err()
}

// dummyHash makes failed logins for unknown users take as long as real ones,
// so response timing doesn't reveal which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcrypt.DefaultCost)

// CheckAdminPassword returns ErrBadLogin for an unknown user or wrong password.
func (s *Store) CheckAdminPassword(ctx context.Context, username, password string) error {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE username = ?`, username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return ErrBadLogin
	}
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return ErrBadLogin
	}
	return nil
}

// Sessions: the cookie holds a random token; only its SHA-256 is stored, so
// a leaked database can't be used to hijack a login.

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CreateSession returns a new session token for username.
func (s *Store) CreateSession(ctx context.Context, username string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, username, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		hashToken(token), username, now.Add(ttl).Unix(), now.Unix())
	return token, err
}

// SessionUser returns the admin a live session token belongs to.
func (s *Store) SessionUser(ctx context.Context, token string) (string, error) {
	var user string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		hashToken(token), time.Now().Unix()).Scan(&user)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return user, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}
