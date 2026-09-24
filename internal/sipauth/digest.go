// Package sipauth implements SIP digest authentication (RFC 3261 §22,
// RFC 2617 MD5 with qop=auth).
//
// Nonces are stateless: each one is a timestamp signed with a per-process
// HMAC key, so the server keeps no per-challenge state and any number of
// phones can authenticate concurrently. A restart invalidates outstanding
// nonces, which phones handle by simply re-authenticating.
package sipauth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/icholy/digest"
)

var (
	ErrNoCredentials = errors.New("no credentials")
	ErrMalformed     = errors.New("malformed credentials")
	ErrStaleNonce    = errors.New("stale nonce")
	ErrBadNonce      = errors.New("invalid nonce")
	ErrBadResponse   = errors.New("wrong password")
)

// Authenticator issues challenges and verifies digest responses.
type Authenticator struct {
	Realm    string
	NonceTTL time.Duration
	key      []byte
	now      func() time.Time
}

func New(realm string) *Authenticator {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Authenticator{Realm: realm, NonceTTL: 5 * time.Minute, key: key, now: time.Now}
}

// Challenge returns a WWW-Authenticate / Proxy-Authenticate header value.
// stale=true tells the phone its password was right but the nonce expired,
// so it retries silently instead of prompting.
func (a *Authenticator) Challenge(stale bool) string {
	c := digest.Challenge{
		Realm:     a.Realm,
		Nonce:     a.newNonce(),
		Algorithm: "MD5",
		QOP:       []string{"auth"},
		Stale:     stale,
	}
	return c.String()
}

// Parse extracts digest credentials from an Authorization header value.
func Parse(header string) (*digest.Credentials, error) {
	if header == "" {
		return nil, ErrNoCredentials
	}
	c, err := digest.ParseCredentials(header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.Username == "" || c.Nonce == "" || c.Response == "" {
		return nil, ErrMalformed
	}
	if c.Algorithm != "" && !strings.EqualFold(c.Algorithm, "MD5") {
		return nil, fmt.Errorf("%w: unsupported algorithm %s", ErrMalformed, c.Algorithm)
	}
	return c, nil
}

// Verify checks credentials for method against the extension's secret.
// On ErrStaleNonce the caller should re-challenge with stale=true.
func (a *Authenticator) Verify(c *digest.Credentials, method, secret string) error {
	if c.Realm != a.Realm {
		return fmt.Errorf("%w: realm %q", ErrMalformed, c.Realm)
	}
	expected := Response(c, method, secret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.ToLower(c.Response))) != 1 {
		// Check the password before the nonce's age so a stale nonce with a
		// wrong password counts as a failure, not a harmless retry.
		if err := a.checkNonce(c.Nonce); errors.Is(err, ErrBadNonce) {
			return err
		}
		return ErrBadResponse
	}
	return a.checkNonce(c.Nonce)
}

// Response computes the expected digest response for the given credentials.
func Response(c *digest.Credentials, method, secret string) string {
	ha1 := md5hex(c.Username + ":" + c.Realm + ":" + secret)
	ha2 := md5hex(method + ":" + c.URI)
	if c.QOP == "" {
		return md5hex(ha1 + ":" + c.Nonce + ":" + ha2)
	}
	nc := fmt.Sprintf("%08x", c.Nc)
	return md5hex(ha1 + ":" + c.Nonce + ":" + nc + ":" + c.Cnonce + ":" + c.QOP + ":" + ha2)
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// Nonce layout: base64url(8-byte unix-nano timestamp || 16-byte HMAC prefix).
func (a *Authenticator) newNonce() string {
	buf := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(buf, uint64(a.now().UnixNano()))
	return base64.RawURLEncoding.EncodeToString(append(buf, a.sign(buf)...))
}

func (a *Authenticator) checkNonce(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 24 {
		return ErrBadNonce
	}
	if !hmac.Equal(raw[8:], a.sign(raw[:8])) {
		return ErrBadNonce
	}
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(raw[:8])))
	if a.now().Sub(issued) > a.NonceTTL {
		return ErrStaleNonce
	}
	return nil
}

func (a *Authenticator) sign(ts []byte) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(a.Realm))
	m.Write(ts)
	return m.Sum(nil)[:16]
}
