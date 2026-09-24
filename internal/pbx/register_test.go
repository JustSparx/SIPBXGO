package pbx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// testPBX starts a PBX on a free localhost UDP port with extensions 101 and
// 102 (password "pw101" / "pw102") and returns its address and store.
func testPBX(t *testing.T, banThreshold int) (string, *store.Store) {
	t.Helper()
	srv, st := startPBX(t, banThreshold)
	return srv.UDPAddr(), st
}

// startPBX is testPBX returning the server itself.
func startPBX(t *testing.T, banThreshold int) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, n := range []string{"101", "102"} {
		if err := st.CreateExtension(ctx, &store.Extension{Number: n, Secret: "pw" + n, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{
		SIPAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", Realm: "sipbxgo", MinExpires: 60, MaxExpires: 300,
		BanThreshold: banThreshold, BanWindow: time.Minute, BanDuration: time.Minute,
		RTPPortMin: 31000, RTPPortMax: 31999, RingTimeout: 5 * time.Second, MediaTimeout: time.Minute,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	// Bound synchronously, so the socket is live before any test packet is sent.
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		if err := srv.Serve(runCtx); err != nil {
			t.Logf("pbx serve: %v", err)
		}
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return srv, st
}

type phone struct {
	t      *testing.T
	client *sipgo.Client
	pbx    string
}

func newPhone(t *testing.T, pbx string) *phone {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("TestPhone/1.0"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := sipgo.NewClient(ua, sipgo.WithClientHostname("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); ua.Close() })
	return &phone{t: t, client: c, pbx: pbx}
}

// register sends REGISTER for ext (To/From) authenticating as user/pass and
// returns the final response, or nil if the server never answered.
func (p *phone) register(ext, user, pass string, expires int) *sip.Response {
	p.t.Helper()
	var uri sip.Uri
	if err := sip.ParseUri(fmt.Sprintf("sip:%s@%s", ext, p.pbx), &uri); err != nil {
		p.t.Fatal(err)
	}
	req := sip.NewRequest(sip.REGISTER, uri)
	req.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:%s@192.168.1.50:5060>", ext)))
	req.AppendHeader(sip.NewHeader("Expires", fmt.Sprint(expires)))
	req.AppendHeader(sip.NewHeader("User-Agent", "TestPhone/1.0"))
	req.SetTransport("UDP")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := p.client.Do(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		return nil
	}
	if res.StatusCode != 401 {
		return res
	}
	res, err = p.client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: user, Password: pass})
	if err != nil {
		return nil
	}
	return res
}

func TestRegisterFlow(t *testing.T) {
	addr, st := testPBX(t, 100)
	p := newPhone(t, addr)

	// Good credentials: default expiry clamped to MaxExpires.
	res := p.register("101", "101", "pw101", 3600)
	if res == nil || res.StatusCode != 200 {
		t.Fatalf("register: %v", res)
	}
	c, ok := res.GetHeader("Contact").(*sip.ContactHeader)
	if !ok {
		t.Fatalf("no contact in 200: %v", res)
	}
	if exp, _ := c.Params.Get("expires"); exp != "300" && exp != "299" {
		t.Fatalf("expires=%s, want clamped to 300", exp)
	}
	regs, _ := st.ListRegistrations(context.Background(), "101")
	if len(regs) != 1 {
		t.Fatalf("got %d bindings, want 1", len(regs))
	}
	if regs[0].Transport != "UDP" || regs[0].UserAgent != "TestPhone/1.0" {
		t.Fatalf("binding not stored correctly: %+v", *regs[0])
	}

	cases := []struct {
		name             string
		ext, user, pass  string
		expires, wantRes int
	}{
		{"wrong password", "101", "101", "nope", 120, 403},
		{"unknown extension", "999", "999", "x", 120, 403},
		{"register someone else", "102", "101", "pw101", 120, 403},
		{"too brief", "101", "101", "pw101", 30, 423},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := p.register(tc.ext, tc.user, tc.pass, tc.expires)
			if res == nil || res.StatusCode != tc.wantRes {
				t.Fatalf("got %v, want %d", res, tc.wantRes)
			}
		})
	}

	// Expires: 0 removes the binding.
	if res := p.register("101", "101", "pw101", 0); res == nil || res.StatusCode != 200 {
		t.Fatalf("unregister: %v", res)
	}
	if regs, _ := st.ListRegistrations(context.Background(), "101"); len(regs) != 0 {
		t.Fatalf("binding survived unregister: %+v", regs)
	}
}

func TestBruteForceGetsBanned(t *testing.T) {
	addr, _ := testPBX(t, 3)
	p := newPhone(t, addr)

	for i := 0; i < 3; i++ {
		if res := p.register("101", "101", "guess", 120); res == nil || res.StatusCode != 403 {
			t.Fatalf("attempt %d: got %v, want 403", i, res)
		}
	}
	// Now banned: even the right password gets no answer at all.
	if res := p.register("101", "101", "pw101", 120); res != nil {
		t.Fatalf("banned IP got a response: %d", res.StatusCode)
	}
}
