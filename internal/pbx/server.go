// Package pbx assembles the SIP server: transports, request routing and the
// components behind them (registrar, call engine, media relay).
package pbx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/audio"
	"github.com/JustSparx/SIPBXGO/internal/b2bua"
	"github.com/JustSparx/SIPBXGO/internal/conference"
	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/media"
	"github.com/JustSparx/SIPBXGO/internal/registrar"
	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/sipauth"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/JustSparx/SIPBXGO/internal/tlscert"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Version is set at build time via -ldflags.
var Version = "1.0.0"

const allowMethods = b2bua.AllowMethods + ", REGISTER"

type Server struct {
	cfg      *config.Config
	store    *store.Store
	log      *slog.Logger
	publicIP netip.Addr

	ua        *sipgo.UserAgent
	sip       *sipgo.Server
	client    *sipgo.Client
	bans      *security.BanList
	guard     *sipauth.Guard
	registrar *registrar.Registrar
	engine    *b2bua.Engine

	udp net.PacketConn
	tcp net.Listener
	tls net.Listener // nil when TLS is off

	cert *tlscert.Loader // nil when TLS is off
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	publicIP, err := resolvePublicIP(cfg.PublicIP)
	if err != nil {
		return nil, err
	}
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent("SIPBXGO/"+Version),
		sipgo.WithUserAgentHostname(publicIP.String()),
	)
	if err != nil {
		return nil, fmt.Errorf("sip user agent: %w", err)
	}
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(log))
	if err != nil {
		ua.Close()
		return nil, fmt.Errorf("sip server: %w", err)
	}
	// Via host is the public IP; the port is filled from the socket used.
	client, err := sipgo.NewClient(ua, sipgo.WithClientHostname(publicIP.String()))
	if err != nil {
		ua.Close()
		return nil, fmt.Errorf("sip client: %w", err)
	}

	bans := security.NewBanList(cfg.BanThreshold, cfg.BanWindow, cfg.BanDuration, cfg.TrustedNets)
	guard := &sipauth.Guard{Auth: sipauth.New(cfg.Realm), Exts: st, Bans: bans, Log: log}
	music, err := loadHoldMusic(cfg.HoldMusic)
	if err != nil {
		ua.Close()
		return nil, err
	}
	var loop *media.Loop
	if music != nil {
		loop = media.NewLoop(music)
	}
	engine := b2bua.New(
		b2bua.Config{RingTimeout: cfg.RingTimeout, MediaTimeout: cfg.MediaTimeout, HoldMusic: loop, RoomMusic: music},
		st, guard, media.NewPortPool(cfg.RTPPortMin, cfg.RTPPortMax), client, log)

	s := &Server{
		cfg:       cfg,
		store:     st,
		log:       log,
		publicIP:  publicIP,
		ua:        ua,
		sip:       srv,
		client:    client,
		bans:      bans,
		guard:     guard,
		registrar: registrar.New(st, guard, cfg.MinExpires, cfg.MaxExpires, log),
		engine:    engine,
	}

	if cfg.TLSEnabled() {
		if cfg.TLSAcmeJSON != "" {
			s.cert = tlscert.FromTraefik(cfg.TLSAcmeJSON, cfg.TLSDomain, log)
		} else {
			s.cert = tlscert.FromFiles(cfg.TLSCert, cfg.TLSKey, log)
		}
		if err := s.cert.Load(); err != nil {
			ua.Close()
			return nil, fmt.Errorf("TLS certificate: %w", err)
		}
	}

	srv.OnRegister(s.guarded(s.registrar.HandleRegister))
	srv.OnOptions(s.guarded(s.handleOptions))
	srv.OnInvite(s.guarded(engine.HandleInvite))
	srv.OnAck(s.guarded(engine.HandleAck))
	srv.OnBye(s.guarded(engine.HandleBye))
	srv.OnCancel(s.guarded(engine.HandleCancel))
	srv.OnInfo(s.guarded(engine.HandleInDialog))
	srv.OnUpdate(s.guarded(engine.HandleInDialog))
	srv.OnRefer(s.guarded(engine.HandleRefer))
	srv.OnNoRoute(s.guarded(s.handleNotAllowed))
	return s, nil
}

// resolvePublicIP uses the configured address, or else the local address
// this host would use to reach the internet (correct on a typical VPS whose
// public IP is on its interface; set SIPBX_PUBLIC_IP when behind NAT).
func resolvePublicIP(configured string) (netip.Addr, error) {
	if configured != "" {
		return netip.ParseAddr(configured)
	}
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET; no packet is sent
	if err != nil {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	defer conn.Close()
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

// loadHoldMusic returns the music (8 kHz PCM) to play on hold and to
// someone alone in a conference room: the built-in music, a WAV file, or
// nil for silence.
func loadHoldMusic(setting string) ([]int16, error) {
	switch strings.ToLower(setting) {
	case "off", "none", "silence":
		return nil, nil
	case "", "builtin", "default":
		return audio.HoldMusic(), nil
	}
	pcm, err := audio.LoadWAV(setting)
	if err != nil {
		return nil, fmt.Errorf("SIPBX_HOLD_MUSIC: %w", err)
	}
	if len(pcm) < audio.SampleRate {
		return nil, fmt.Errorf("SIPBX_HOLD_MUSIC: %s is shorter than a second", setting)
	}
	return pcm, nil
}

// PublicIP is the address advertised to phones.
func (s *Server) PublicIP() netip.Addr { return s.publicIP }

// guarded drops requests from banned IPs and scanners before h sees them.
// Dropping means no response at all: scanners learn nothing.
func (s *Server) guarded(h sipgo.RequestHandler) sipgo.RequestHandler {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		if s.guard.Drop(req) {
			return
		}
		h(req, tx)
		if req.IsInvite() {
			// sipgo hands the ACK for a non-2xx answer (401, 486...) to the
			// application; consume it so it isn't logged as "ACK missed".
			go func() {
				select {
				case <-tx.Acks():
				case <-tx.Done():
				}
			}()
		}
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
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", allowMethods))
	tx.Respond(res)
}

// UseCertificate enables SIP over TLS with the given certificate source
// (overriding configuration). Call before Listen.
func (s *Server) UseCertificate(l *tlscert.Loader) { s.cert = l }

// TLSInfo describes the TLS certificate in use, or nil when TLS is off.
func (s *Server) TLSInfo() *tlscert.Info {
	if s.cert == nil {
		return nil
	}
	i := s.cert.Info()
	return &i
}

// TLSPort is the SIP over TLS port, or 0 when TLS is off.
func (s *Server) TLSPort() int {
	if s.tls == nil {
		return 0
	}
	return s.tls.Addr().(*net.TCPAddr).Port
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

	if s.cert != nil {
		addr := s.cfg.TLSAddr
		if addr == "" || addr == "off" {
			addr = ":5061"
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			udp.Close()
			tcp.Close()
			return fmt.Errorf("listen tls %s: %w", addr, err)
		}
		s.tls = tls.NewListener(ln, s.cert.TLSConfig())
	}

	udpAddr := udp.LocalAddr().(*net.UDPAddr)
	tcpAddr := tcp.Addr().(*net.TCPAddr)
	laddr := sip.Addr{IP: udpAddr.IP, Port: udpAddr.Port}
	s.engine.Bind(s.publicIP, udpAddr.Port, tcpAddr.Port, s.TLSPort(), s.cfg.TLSDomain, laddr)
	return nil
}

// UDPAddr is the bound UDP address (useful when SIPAddr uses port 0).
func (s *Server) UDPAddr() string { return s.udp.LocalAddr().String() }

// Engine exposes the call engine (active calls, for the UI and tests).
func (s *Server) Engine() *b2bua.Engine { return s.engine }

// Conferences lists conference rooms in use and who is in them.
func (s *Server) Conferences() []conference.RoomStatus { return s.engine.Conferences() }

// ActiveCalls lists connected calls.
func (s *Server) ActiveCalls() []*b2bua.Call { return s.engine.ActiveCalls() }

// Bans lists currently banned IPs.
func (s *Server) Bans() []security.Ban { return s.bans.Active() }

// Unban lifts a ban.
func (s *Server) Unban(ip netip.Addr) { s.bans.Unban(ip) }

// SIPPort is the port phones register to.
func (s *Server) SIPPort() int { return s.udp.LocalAddr().(*net.UDPAddr).Port }

// Serve handles SIP traffic until ctx is cancelled or a transport fails.
// Listen must have been called first.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 3)
	go func() { errc <- s.sip.ServeUDP(s.udp) }()
	go func() { errc <- s.sip.ServeTCP(s.tcp) }()
	s.log.Info("SIP listening", "udp", s.udp.LocalAddr(), "tcp", s.tcp.Addr(),
		"public_ip", s.publicIP, "realm", s.cfg.Realm,
		"rtp_ports", fmt.Sprintf("%d-%d", s.cfg.RTPPortMin, s.cfg.RTPPortMax))
	if s.tls != nil {
		go func() { errc <- s.sip.ServeTLS(s.tls) }()
		go s.cert.Watch(ctx, time.Minute)
		info := s.cert.Info()
		s.log.Info("SIP over TLS listening", "addr", s.tls.Addr(), "certificate", info.Source,
			"names", info.Names, "expires", info.NotAfter.Format(time.DateOnly))
	} else {
		s.log.Info("SIP over TLS off (no certificate configured)")
	}

	go s.housekeeping(ctx)
	go s.engine.Monitor(ctx)

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			err = fmt.Errorf("sip transport: %w", err)
		}
	}
	cancel()
	// Hang up gracefully so phones don't sit on dead calls after a restart.
	s.engine.HangupAll()
	s.udp.Close()
	s.tcp.Close()
	if s.tls != nil {
		s.tls.Close()
	}
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
