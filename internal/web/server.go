// Package web is SIPBXGO's admin interface: server-rendered HTML with a
// sprinkle of JavaScript for live refresh, embedded in the binary.
//
// It is meant to sit behind a TLS reverse proxy (Traefik, Caddy, nginx) and
// listens on loopback by default.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/b2bua"
	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/JustSparx/SIPBXGO/internal/tlscert"
)

//go:embed templates static
var assets embed.FS

// PBX is the live state the UI shows and controls.
type PBX interface {
	ActiveCalls() []*b2bua.Call
	Bans() []security.Ban
	Unban(ip netip.Addr)
	PublicIP() netip.Addr
	SIPPort() int
	TLSPort() int           // 0 when SIP over TLS is off
	TLSInfo() *tlscert.Info // nil when SIP over TLS is off
}

type Server struct {
	cfg     *config.Config
	store   *store.Store
	pbx     PBX
	log     *slog.Logger
	version string

	pages      map[string]*template.Template
	loginLimit *security.BanList
	handler    http.Handler
}

// SessionTTL is how long a login lasts.
const SessionTTL = 7 * 24 * time.Hour

func New(cfg *config.Config, st *store.Store, pbx PBX, log *slog.Logger, version string) (*Server, error) {
	s := &Server{
		cfg: cfg, store: st, pbx: pbx, log: log, version: version,
		// 10 wrong passwords from one IP in 15 minutes locks it out for 15.
		loginLimit: security.NewBanList(10, 15*time.Minute, 15*time.Minute, nil),
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)

	auth := func(h http.HandlerFunc) http.Handler { return s.requireLogin(h) }
	mux.Handle("GET /{$}", auth(s.dashboard))
	mux.Handle("GET /live/dashboard", auth(s.dashboardLive))
	mux.Handle("GET /extensions", auth(s.extensions))
	mux.Handle("POST /extensions", auth(s.createExtension))
	mux.Handle("GET /extensions/{number}", auth(s.extension))
	mux.Handle("GET /live/extensions/{number}", auth(s.extensionLive))
	mux.Handle("POST /extensions/{number}", auth(s.updateExtension))
	mux.Handle("POST /extensions/{number}/secret", auth(s.resetSecret))
	mux.Handle("POST /extensions/{number}/delete", auth(s.deleteExtension))
	mux.Handle("GET /calls", auth(s.calls))
	mux.Handle("GET /security", auth(s.securityPage))
	mux.Handle("POST /security/unban", auth(s.unban))
	mux.Handle("GET /account", auth(s.account))
	mux.Handle("POST /account/password", auth(s.changePassword))

	// Reject cross-site form posts (CSRF) using Sec-Fetch-Site / Origin.
	csrf := http.NewCrossOriginProtection()
	return securityHeaders(csrf.Handler(mux))
}

// ServeHTTP makes Server usable directly in tests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("web UI listen %s: %w", s.cfg.HTTPAddr, err)
	}
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	s.log.Info("web UI listening", "addr", ln.Addr())

	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.store.PurgeExpiredSessions(ctx)
				s.loginLimit.Sweep()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func staticHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// fromProxy reports whether the request came through a local reverse proxy,
// whose X-Forwarded-* headers can then be trusted.
func fromProxy(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip.IsLoopback() || ip.IsPrivate()
}

// clientIP is the browser's address, looking through a trusted local proxy.
func clientIP(r *http.Request) netip.Addr {
	if fromProxy(r) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// The proxy appends the address it saw, so the last entry is the
			// one it vouches for.
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.Unmap()
			}
		}
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// isHTTPS reports whether the browser is talking HTTPS (directly or via proxy).
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || (fromProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}
