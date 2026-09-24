package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/b2bua"
	"github.com/JustSparx/SIPBXGO/internal/conference"
	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/JustSparx/SIPBXGO/internal/tlscert"
)

type fakePBX struct {
	bans     []security.Ban
	unbanned []netip.Addr
	tls      *tlscert.Info
	rooms    []conference.RoomStatus
}

func (f *fakePBX) ActiveCalls() []*b2bua.Call { return nil }
func (f *fakePBX) Bans() []security.Ban       { return f.bans }
func (f *fakePBX) Unban(ip netip.Addr)        { f.unbanned = append(f.unbanned, ip) }
func (f *fakePBX) PublicIP() netip.Addr       { return netip.MustParseAddr("203.0.113.10") }
func (f *fakePBX) SIPPort() int               { return 5060 }
func (f *fakePBX) TLSInfo() *tlscert.Info     { return f.tls }
func (f *fakePBX) Conferences() []conference.RoomStatus {
	return f.rooms
}
func (f *fakePBX) TLSPort() int {
	if f.tls == nil {
		return 0
	}
	return 5061
}

type harness struct {
	t      *testing.T
	st     *store.Store
	pbx    *fakePBX
	srv    *httptest.Server
	client *http.Client
}

const adminPass = "correct-horse-battery"

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateAdmin(context.Background(), "admin", adminPass); err != nil {
		t.Fatal(err)
	}
	pbx := &fakePBX{}
	cfg := &config.Config{SIPDomain: "pbx.example.com", BanThreshold: 5, BanWindow: 10 * time.Minute, BanDuration: time.Hour}
	ui, err := New(cfg, st, pbx, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ui)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{t: t, st: st, pbx: pbx, srv: srv, client: client}
}

// do sends a request as a same-origin browser would.
func (h *harness) do(method, path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func (h *harness) login() {
	h.t.Helper()
	res, _ := h.do("POST", "/login", url.Values{"username": {"admin"}, "password": {adminPass}, "next": {"/"}})
	if res.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login: status %d", res.StatusCode)
	}
}

func expect(t *testing.T, res *http.Response, body string, status int, contains ...string) {
	t.Helper()
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d\n%s", res.Request.Method, res.Request.URL.Path, res.StatusCode, status, body)
	}
	for _, c := range contains {
		if !strings.Contains(body, c) {
			t.Errorf("%s: missing %q", res.Request.URL.Path, c)
		}
	}
}

func TestLoginRequired(t *testing.T) {
	h := newHarness(t)
	res, _ := h.do("GET", "/extensions", nil)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login?next=%2Fextensions" {
		t.Fatalf("got %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := h.do("GET", "/live/dashboard", nil)
	expect(t, res, body, http.StatusUnauthorized)
	res, body = h.do("POST", "/extensions", url.Values{"number": {"101"}})
	expect(t, res, body, http.StatusUnauthorized)
	res, body = h.do("GET", "/healthz", nil)
	expect(t, res, body, http.StatusOK, "ok")
}

func TestLoginFlow(t *testing.T) {
	h := newHarness(t)
	res, body := h.do("GET", "/login", nil)
	expect(t, res, body, http.StatusOK, "Sign in")
	if res.Header.Get("Content-Security-Policy") == "" || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security headers missing")
	}

	res, body = h.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"nope"}})
	expect(t, res, body, http.StatusUnauthorized, "Wrong username or password")

	// Open redirects are neutralized.
	res, _ = h.do("POST", "/login", url.Values{"username": {"admin"}, "password": {adminPass}, "next": {"//evil.example"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("login redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bad session cookie: %+v", session)
	}

	res, body = h.do("GET", "/", nil)
	expect(t, res, body, http.StatusOK, "Dashboard", "Calls in progress", "Registered phones")

	h.do("POST", "/logout", url.Values{})
	res, _ = h.do("GET", "/", nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("still logged in after logout: %d", res.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 10; i++ {
		h.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"guess"}})
	}
	res, body := h.do("POST", "/login", url.Values{"username": {"admin"}, "password": {adminPass}})
	expect(t, res, body, http.StatusTooManyRequests, "Too many failed attempts")
}

func TestCrossSiteFormRejected(t *testing.T) {
	h := newHarness(t)
	h.login()
	req, _ := http.NewRequest("POST", h.srv.URL+"/extensions", strings.NewReader("number=101"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST: status %d, want 403", res.StatusCode)
	}
	if _, err := h.st.GetExtension(context.Background(), "101"); err == nil {
		t.Fatal("cross-site POST created an extension")
	}
}

func TestExtensionLifecycle(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()

	res, body := h.do("POST", "/extensions", url.Values{"number": {"7"}, "name": {"Bad"}})
	expect(t, res, body, http.StatusBadRequest, "2 to 8 digits")

	res, _ = h.do("POST", "/extensions", url.Values{"number": {"101"}, "name": {"Kitchen"}})
	if loc := res.Header.Get("Location"); loc != "/extensions/101?ok=created" {
		t.Fatalf("create redirect: %d %q", res.StatusCode, loc)
	}
	ext, err := h.st.GetExtension(ctx, "101")
	if err != nil || len(ext.Secret) != 16 {
		t.Fatalf("created extension: %+v %v", ext, err)
	}
	res, body = h.do("GET", "/extensions/101?ok=created", nil)
	expect(t, res, body, http.StatusOK, "Extension created", "pbx.example.com", ext.Secret, "Kitchen")

	res, body = h.do("POST", "/extensions", url.Values{"number": {"101"}})
	expect(t, res, body, http.StatusBadRequest, "already exists")

	res, body = h.do("GET", "/extensions", nil)
	expect(t, res, body, http.StatusOK, "Kitchen", "Offline")
	res, body = h.do("GET", "/live/extensions/101", nil)
	expect(t, res, body, http.StatusOK, "No phone is registered")

	// Rename and disable.
	h.do("POST", "/extensions/101", url.Values{"name": {"Garage"}})
	ext, _ = h.st.GetExtension(ctx, "101")
	if ext.Name != "Garage" || ext.Enabled {
		t.Fatalf("update: %+v", ext)
	}

	// Password: too short, custom, generated.
	res, body = h.do("POST", "/extensions/101/secret", url.Values{"secret": {"short"}})
	expect(t, res, body, http.StatusBadRequest, "at least 8")
	h.do("POST", "/extensions/101/secret", url.Values{"secret": {"a-long-password"}})
	if ext, _ = h.st.GetExtension(ctx, "101"); ext.Secret != "a-long-password" {
		t.Fatalf("custom secret not set: %q", ext.Secret)
	}
	h.do("POST", "/extensions/101/secret", url.Values{})
	if ext, _ = h.st.GetExtension(ctx, "101"); ext.Secret == "a-long-password" {
		t.Fatal("secret not regenerated")
	}

	res, _ = h.do("POST", "/extensions/101/delete", url.Values{})
	if res.Header.Get("Location") != "/extensions?ok=deleted" {
		t.Fatalf("delete redirect: %q", res.Header.Get("Location"))
	}
	res, _ = h.do("GET", "/extensions/101", nil)
	if res.Header.Get("Location") != "/extensions?ok=noextfound" {
		t.Fatalf("deleted extension page: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestDashboardAndCalls(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	h.st.CreateExtension(ctx, &store.Extension{Number: "101", Name: "Kitchen", Secret: "pw-pw-pw-pw", Enabled: true})
	h.st.CreateExtension(ctx, &store.Extension{Number: "102", Name: "Office", Secret: "pw-pw-pw-pw", Enabled: true})
	now := time.Now()
	h.st.SaveRegistration(ctx, &store.Registration{Extension: "101", Contact: "sip:101@10.0.0.5", Source: "198.51.100.7:5061",
		Transport: "UDP", UserAgent: "OBIHAI/OBi1032", ExpiresAt: now.Add(time.Minute), UpdatedAt: now})
	h.st.SaveCall(ctx, &store.CallRecord{ID: "a1", Caller: "101", Callee: "102", Status: store.CallAnswered, HangupBy: "caller",
		StartedAt: now.Add(-time.Minute), AnsweredAt: now.Add(-50 * time.Second), EndedAt: now})
	h.st.SaveCall(ctx, &store.CallRecord{ID: "a2", Caller: "102", Callee: "101", Status: store.CallNoAnswer, HangupBy: "system",
		StartedAt: now, EndedAt: now})

	res, body := h.do("GET", "/live/dashboard", nil)
	expect(t, res, body, http.StatusOK, "OBIHAI/OBi1032", "198.51.100.7:5061", "Offline extensions", "Office")
	if strings.Contains(body, "<html") {
		t.Error("live partial rendered the full layout")
	}

	res, body = h.do("GET", "/calls", nil)
	expect(t, res, body, http.StatusOK, "0:50", "No answer", "Answered")
	res, body = h.do("GET", "/calls?ext=102&page=2", nil)
	expect(t, res, body, http.StatusOK, "No calls involving 102 on this page", "← Newer")
	res, body = h.do("GET", "/extensions/101", nil)
	expect(t, res, body, http.StatusOK, "OBIHAI/OBi1032", "All calls for 101")
}

func TestSecurityPageAndUnban(t *testing.T) {
	h := newHarness(t)
	h.login()
	ip := netip.MustParseAddr("192.0.2.66")
	h.pbx.bans = []security.Ban{{Addr: ip, Until: time.Now().Add(30 * time.Minute)}}

	res, body := h.do("GET", "/security", nil)
	expect(t, res, body, http.StatusOK, "192.0.2.66", "30m", "banned for <strong>1h</strong>")
	h.do("POST", "/security/unban", url.Values{"ip": {"192.0.2.66"}})
	if len(h.pbx.unbanned) != 1 || h.pbx.unbanned[0] != ip {
		t.Fatalf("unban not applied: %v", h.pbx.unbanned)
	}
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	h.login()
	res, body := h.do("GET", "/account", nil)
	expect(t, res, body, http.StatusOK, "Change your password", "admin")

	res, body = h.do("POST", "/account/password", url.Values{"current": {"wrong"}, "new": {"new-password-1"}, "confirm": {"new-password-1"}})
	expect(t, res, body, http.StatusUnauthorized, "current password is wrong")
	res, body = h.do("POST", "/account/password", url.Values{"current": {adminPass}, "new": {"new-password-1"}, "confirm": {"different-one"}})
	expect(t, res, body, http.StatusBadRequest, "don&#39;t match")
	res, body = h.do("POST", "/account/password", url.Values{"current": {adminPass}, "new": {"short"}, "confirm": {"short"}})
	expect(t, res, body, http.StatusBadRequest, "at least 10")

	res, _ = h.do("POST", "/account/password", url.Values{"current": {adminPass}, "new": {"new-password-1"}, "confirm": {"new-password-1"}})
	if res.Header.Get("Location") != "/account?ok=password" {
		t.Fatalf("change: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// This browser stays signed in; the new password works.
	res, body = h.do("GET", "/account?ok=password", nil)
	expect(t, res, body, http.StatusOK, "Your password was changed")
	if err := h.st.CheckAdminPassword(context.Background(), "admin", "new-password-1"); err != nil {
		t.Fatal(err)
	}
}

func TestFormatting(t *testing.T) {
	cases := map[time.Duration]string{
		0: "0s", 10 * time.Second: "10s", 59 * time.Second: "59s", 5 * time.Minute: "5m",
		time.Hour: "1h", 90 * time.Minute: "1h30m", -time.Second: "0s",
	}
	for d, want := range cases {
		if got := roundDur(d); got != want {
			t.Errorf("roundDur(%v) = %q, want %q", d, got, want)
		}
	}
	if clock(65*time.Second) != "1:05" || clock(3725*time.Second) != "1:02:05" {
		t.Errorf("clock: %s %s", clock(65*time.Second), clock(3725*time.Second))
	}
}

func TestEncryptionUI(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	h.st.CreateExtension(ctx, &store.Extension{Number: "101", Name: "Kitchen", Secret: "pw-pw-pw-pw", Enabled: true})

	// TLS off: setup card shows plain settings, security page says so.
	res, body := h.do("GET", "/extensions/101", nil)
	expect(t, res, body, http.StatusOK, "Needs SIP over TLS", "(TCP if the router mangles SIP)")
	res, body = h.do("GET", "/security", nil)
	expect(t, res, body, http.StatusOK, "SIP over TLS is not configured")

	// TLS on.
	h.pbx.tls = &tlscert.Info{Source: "Traefik /traefik/acme.json", Names: []string{"pbx.example.com"}, NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	res, body = h.do("GET", "/extensions/101", nil)
	expect(t, res, body, http.StatusOK, "5061", "SRTP (SDES", "Only TLS registrations")
	res, body = h.do("GET", "/security", nil)
	expect(t, res, body, http.StatusOK, "pbx.example.com", "in 59 days", "Traefik /traefik/acme.json")

	// Toggle "require encryption".
	h.do("POST", "/extensions/101", url.Values{"name": {"Kitchen"}, "enabled": {"on"}, "require_tls": {"on"}})
	if ext, _ := h.st.GetExtension(ctx, "101"); !ext.RequireTLS {
		t.Fatal("require_tls not saved")
	}
	res, body = h.do("GET", "/extensions/101", nil)
	expect(t, res, body, http.StatusOK, "refused: this extension requires encryption")

	// Encryption shows in call history.
	now := time.Now()
	h.st.SaveCall(ctx, &store.CallRecord{ID: "e1", Caller: "101", Callee: "102", Status: store.CallAnswered,
		StartedAt: now, AnsweredAt: now, EndedAt: now, Encryption: store.EncryptionPartial})
	res, body = h.do("GET", "/calls", nil)
	expect(t, res, body, http.StatusOK, "Partly encrypted")
}

func TestConferenceRoomsUI(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	h.st.CreateExtension(ctx, &store.Extension{Number: "101", Name: "Kitchen", Secret: "pw-pw-pw-pw", Enabled: true})

	res, body := h.do("GET", "/conferences", nil)
	expect(t, res, body, http.StatusOK, "No rooms yet", "No one is in a conference room")

	res, body = h.do("POST", "/conferences", url.Values{"number": {"101"}})
	expect(t, res, body, http.StatusBadRequest, "already an extension number")
	res, body = h.do("POST", "/conferences", url.Values{"number": {"800"}, "pin": {"12ab"}})
	expect(t, res, body, http.StatusBadRequest, "up to 12 digits")

	res, _ = h.do("POST", "/conferences", url.Values{"number": {"800"}, "name": {"Family"}, "pin": {"4321"}})
	if res.Header.Get("Location") != "/conferences?ok=roomadded" {
		t.Fatalf("create: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, body = h.do("POST", "/extensions", url.Values{"number": {"800"}})
	expect(t, res, body, http.StatusBadRequest, "already a conference room")

	h.do("POST", "/conferences/800", url.Values{"name": {"Everyone"}, "pin": {""}})
	if r, _ := h.st.GetRoom(ctx, "800"); r.Name != "Everyone" || r.PIN != "" {
		t.Fatalf("update: %+v", r)
	}

	// Live view with someone in the room.
	h.pbx.rooms = []conference.RoomStatus{{Number: "800", Members: []conference.Member{
		{Ext: "101", Name: "Kitchen", Joined: time.Now().Add(-65 * time.Second), Admitted: true, Secure: true},
		{Ext: "102", Joined: time.Now()},
	}}}
	res, body = h.do("GET", "/live/conferences", nil)
	expect(t, res, body, http.StatusOK, "Everyone", "Kitchen", "1:05", "SRTP", "entering PIN")
	res, body = h.do("GET", "/", nil)
	expect(t, res, body, http.StatusOK, "Conference rooms in use", "Everyone")

	h.do("POST", "/conferences/800/delete", url.Values{})
	if _, err := h.st.GetRoom(ctx, "800"); err == nil {
		t.Fatal("room not deleted")
	}
}
