// Package pbx assembles the SIP server: transports, request routing and the
// components (registrar, and later the B2BUA and media) behind them.
package pbx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/registrar"
	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/sipauth"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Version is set at build time via -ldflags.
var Version = "dev"

const allowMethods = "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER"

type Server struct {
	cfg   *config.Config
	store *store.Store
	log   *slog.Logger

	ua        *sipgo.UserAgent
	sip       *sipgo.Server
	bans      *security.BanList
	guard     *sipauth.Guard
	registrar *registrar.Registrar

	udp net.PacketConn
	tcp net.Listener
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	opts := []sipgo.UserAgentOption{sipgo.WithUserAgent("SIPBXGO/" + Version)}
	if cfg.PublicIP != "" {
		opts = append(opts, sipgo.WithUserAgentHostname(cfg.PublicIP))
	}
	ua, err := sipgo.NewUA(opts...)
	if err != nil {
		return nil, fmt.Errorf("sip user agent: %w", err)
	}
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(log))
	if err != nil {
		ua.Close()
		return nil, fmt.Errorf("sip server: %w", err)
	}

	bans := security.NewBanList(cfg.BanThreshold, cfg.BanWindow, cfg.BanDuration, cfg.TrustedNets)
	guard := &sipauth.Guard{Auth: sipauth.New(cfg.Realm), Exts: st, Bans: bans, Log: log}

	s := &Server{
		cfg:       cfg,
		store:     st,
		log:       log,
		ua:        ua,
		sip:       srv,
		bans:      bans,
		guard:     guard,
		registrar: registrar.New(st, guard, cfg.MinExpires, cfg.MaxExpires, log),
	}

	srv.OnRegister(s.guarded(s.registrar.HandleRegister))
	srv.OnOptions(s.guarded(s.handleOptions))
	srv.OnNoRoute(s.guarded(s.handleNotAllowed))
	return s, nil
}

// guarded drops requests from banned IPs and scanners before h sees them.
// Dropping means no response at all: scanners learn nothing.
func (s *Server) guarded(h sipgo.RequestHandler) sipgo.RequestHandler {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		if s.guard.Drop(req) {
			return
		}
		h(req, tx)
	}
}

// handleOptions answers keepalive/capability probes.
func (s *Server) handleOptions(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", allowMethods))
	res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	tx.Respond(res)
}

func (s *Server) handleNotAllowed(req *sip.Request, tx sip.ServerTransaction) {
	if req.IsAck() {
		return
	}
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", allowMethods))
	tx.Respond(res)
}

// Listen binds the UDP and TCP sockets. It is separate from Serve so bind
// errors (port in use, permission) surface immediately at startup.
func (s *Server) Listen() error {
	udp, err := net.ListenPacket("udp", s.cfg.SIPAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.cfg.SIPAddr, err)
	}
	tcp, err := net.Listen("tcp", s.cfg.SIPAddr)
	if err != nil {
		udp.Close()
		return fmt.Errorf("listen tcp %s: %w", s.cfg.SIPAddr, err)
	}
	s.udp, s.tcp = udp, tcp
	return nil
}

// UDPAddr is the bound UDP address (useful when SIPAddr uses port 0).
func (s *Server) UDPAddr() string { return s.udp.LocalAddr().String() }

// Serve handles SIP traffic until ctx is cancelled or a transport fails.
// Listen must have been called first.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)
	go func() { errc <- s.sip.ServeUDP(s.udp) }()
	go func() { errc <- s.sip.ServeTCP(s.tcp) }()
	s.log.Info("SIP listening", "udp", s.udp.LocalAddr(), "tcp", s.tcp.Addr(),
		"public_ip", s.cfg.PublicIP, "realm", s.cfg.Realm)

	go s.housekeeping(ctx)

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			err = fmt.Errorf("sip transport: %w", err)
		}
	}
	cancel()
	s.udp.Close()
	s.tcp.Close()
	s.sip.Close()
	s.ua.Close()
	return err
}

// housekeeping periodically purges expired registrations and bans.
func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.store.PurgeExpiredRegistrations(ctx); err != nil {
				s.log.Error("purge registrations", "error", err)
			} else if n > 0 {
				s.log.Info("registrations expired", "count", n)
			}
			s.bans.Sweep()
		}
	}
}
