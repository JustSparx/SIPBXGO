package sipauth

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo/sip"
)

// ExtensionLookup is the slice of the store the guard needs.
type ExtensionLookup interface {
	GetExtension(ctx context.Context, number string) (*store.Extension, error)
}

// Guard ties digest auth to extensions and the ban list. Handlers call
// Authorize; it answers the transaction itself on any failure.
type Guard struct {
	Auth *Authenticator
	Exts ExtensionLookup
	Bans *security.BanList
	Log  *slog.Logger
}

// SourceIP returns the network address a request arrived from.
func SourceIP(req *sip.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(req.Source())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// Drop reports whether a request should be silently ignored: its source is
// banned, or it is a known scanner (which gets banned on the spot).
func (g *Guard) Drop(req *sip.Request) bool {
	ip := SourceIP(req)
	if g.Bans.IsBanned(ip) {
		return true
	}
	if h := req.GetHeader("User-Agent"); h != nil && security.IsScannerAgent(h.Value()) {
		if g.Bans.BanNow(ip) {
			g.Log.Warn("banned scanner", "ip", ip, "user_agent", h.Value())
			return true
		}
	}
	return false
}

// Authorize authenticates req against the extension named in its digest
// credentials. It returns the extension on success; otherwise it has already
// responded (401 challenge, 403, or 400) and returns nil.
func (g *Guard) Authorize(req *sip.Request, tx sip.ServerTransaction) *store.Extension {
	ip := SourceIP(req)
	h := req.GetHeader("Authorization")
	if h == nil {
		h = req.GetHeader("Proxy-Authorization")
	}
	if h == nil {
		g.challenge(req, tx, false)
		return nil
	}

	cred, err := Parse(h.Value())
	if err != nil {
		g.fail(ip, "", err)
		tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Authorization", nil))
		return nil
	}

	ext, err := g.Exts.GetExtension(context.Background(), cred.Username)
	if err != nil || !ext.Enabled {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			g.Log.Error("extension lookup", "error", err)
			tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Error", nil))
			return nil
		}
		// Same answer as a wrong password so scanners can't enumerate extensions.
		g.fail(ip, cred.Username, errors.New("unknown or disabled extension"))
		tx.Respond(sip.NewResponseFromRequest(req, 403, "Forbidden", nil))
		return nil
	}

	switch err := g.Auth.Verify(cred, string(req.Method), ext.Secret); {
	case err == nil:
		g.Bans.Succeed(ip)
		return ext
	case errors.Is(err, ErrStaleNonce):
		g.challenge(req, tx, true)
	case errors.Is(err, ErrBadNonce):
		// Usually a nonce from before a restart; re-challenge without penalty.
		g.challenge(req, tx, false)
	default:
		g.fail(ip, cred.Username, err)
		tx.Respond(sip.NewResponseFromRequest(req, 403, "Forbidden", nil))
	}
	return nil
}

func (g *Guard) challenge(req *sip.Request, tx sip.ServerTransaction, stale bool) {
	res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", g.Auth.Challenge(stale)))
	tx.Respond(res)
}

func (g *Guard) fail(ip netip.Addr, user string, reason error) {
	g.Log.Warn("auth failed", "ip", ip, "user", user, "reason", reason)
	if g.Bans.Fail(ip) {
		g.Log.Warn("banned ip after repeated auth failures", "ip", ip, "duration", g.Bans.Duration)
	}
}
