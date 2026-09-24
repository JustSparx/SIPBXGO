package sdp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SDES-SRTP (RFC 4568): keys are exchanged in SDP as
//
//	a=crypto:<tag> <suite> inline:<base64(key||salt)>[|lifetime][|mki:len]
//
// which is only safe when the SDP itself travels over TLS.

// Supported crypto suites, most preferred first. Both use a 16-byte AES key
// and a 14-byte salt; they differ only in the auth tag length.
const (
	SuiteAES80 = "AES_CM_128_HMAC_SHA1_80"
	SuiteAES32 = "AES_CM_128_HMAC_SHA1_32"
)

// KeyLen is the master key+salt length for the supported suites.
const KeyLen = 30

// Crypto is one a=crypto line.
type Crypto struct {
	Tag   int
	Suite string
	Key   []byte // master key (16) || master salt (14)
}

// NewCrypto returns a fresh random key for suite.
func NewCrypto(tag int, suite string) (*Crypto, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Crypto{Tag: tag, Suite: suite, Key: key}, nil
}

// String renders the attribute value (without "a=").
func (c *Crypto) String() string {
	return fmt.Sprintf("crypto:%d %s inline:%s", c.Tag, c.Suite, base64.StdEncoding.EncodeToString(c.Key))
}

// Equal reports whether two crypto lines carry the same suite and key.
func (c *Crypto) Equal(o *Crypto) bool {
	if c == nil || o == nil {
		return c == o
	}
	return c.Suite == o.Suite && string(c.Key) == string(o.Key)
}

func supportedSuite(s string) bool { return s == SuiteAES80 || s == SuiteAES32 }

var errCryptoSyntax = errors.New("sdp: malformed a=crypto")

// parseCrypto parses the value after "a=crypto:". Lines with unsupported
// suites return (nil, nil) so callers can skip them.
func parseCrypto(v string) (*Crypto, error) {
	f := strings.Fields(v)
	if len(f) < 3 {
		return nil, errCryptoSyntax
	}
	tag, err := strconv.Atoi(f[0])
	if err != nil || tag < 0 {
		return nil, errCryptoSyntax
	}
	if !supportedSuite(f[1]) {
		return nil, nil
	}
	// Only the first key param is used; multiple keys are rare.
	param := strings.SplitN(f[2], ";", 2)[0]
	b64, ok := strings.CutPrefix(param, "inline:")
	if !ok {
		return nil, errCryptoSyntax
	}
	parts := strings.Split(b64, "|")
	for _, p := range parts[1:] {
		// A master key identifier (MKI) changes the packet format; the relay
		// doesn't support it, so treat such lines as unusable.
		if strings.Contains(p, ":") {
			return nil, nil
		}
	}
	key, err := base64.StdEncoding.DecodeString(padBase64(parts[0]))
	if err != nil || len(key) != KeyLen {
		return nil, errCryptoSyntax
	}
	return &Crypto{Tag: tag, Suite: f[1], Key: key}, nil
}

// Some phones omit base64 padding.
func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}
