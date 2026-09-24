package sipauth

import (
	"errors"
	"testing"
	"time"

	"github.com/icholy/digest"
)

// clientCreds answers a challenge the way a phone would, using an
// independent digest implementation.
func clientCreds(t *testing.T, challenge, method, uri, user, pass string) *digest.Credentials {
	t.Helper()
	chal, err := digest.ParseChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := digest.Digest(chal, digest.Options{Method: method, URI: uri, Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through the header form, as it would arrive on the wire.
	parsed, err := Parse(cred.String())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestVerify(t *testing.T) {
	a := New("sipbxgo")
	chal := a.Challenge(false)

	good := clientCreds(t, chal, "REGISTER", "sip:example.com", "101", "s3cret")
	if err := a.Verify(good, "REGISTER", "s3cret"); err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	if err := a.Verify(good, "REGISTER", "wrong"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("wrong secret: got %v, want ErrBadResponse", err)
	}
	if err := a.Verify(good, "INVITE", "s3cret"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("wrong method: got %v, want ErrBadResponse", err)
	}
}

func TestVerifyStaleNonce(t *testing.T) {
	a := New("sipbxgo")
	start := time.Now()
	a.now = func() time.Time { return start }
	cred := clientCreds(t, a.Challenge(false), "REGISTER", "sip:x", "101", "pw")

	a.now = func() time.Time { return start.Add(a.NonceTTL + time.Second) }
	if err := a.Verify(cred, "REGISTER", "pw"); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("got %v, want ErrStaleNonce", err)
	}
	// A wrong password must not hide behind "stale".
	if err := a.Verify(cred, "REGISTER", "nope"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("got %v, want ErrBadResponse", err)
	}
}

func TestVerifyForeignNonce(t *testing.T) {
	a, b := New("sipbxgo"), New("sipbxgo") // different keys, e.g. before/after restart
	cred := clientCreds(t, a.Challenge(false), "REGISTER", "sip:x", "101", "pw")
	if err := b.Verify(cred, "REGISTER", "pw"); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("got %v, want ErrBadNonce", err)
	}
}

func TestVerifyWrongRealm(t *testing.T) {
	a := New("sipbxgo")
	cred := clientCreds(t, a.Challenge(false), "REGISTER", "sip:x", "101", "pw")
	cred.Realm = "other"
	if err := a.Verify(cred, "REGISTER", "pw"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// RFC 2617 §3.5 worked example (HTTP, but the arithmetic is identical).
func TestResponseRFC2617Vector(t *testing.T) {
	c := &digest.Credentials{
		Username: "Mufasa",
		Realm:    "testrealm@host.com",
		Nonce:    "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		URI:      "/dir/index.html",
		QOP:      "auth",
		Nc:       1,
		Cnonce:   "0a4f113b",
	}
	if got, want := Response(c, "GET", "Circle Of Life"), "6629fae49393a05397450978507c4ef1"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, h := range []string{"", "Basic abc", `Digest username="101"`} {
		if _, err := Parse(h); err == nil {
			t.Errorf("Parse(%q) succeeded", h)
		}
	}
}
