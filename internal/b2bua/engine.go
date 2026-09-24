// Package b2bua connects calls between extensions.
//
// SIPBXGO is a back-to-back user agent: a caller's INVITE ends at the PBX
// (the "A leg") and the PBX places its own INVITE to the callee (the "B leg"),
// relaying audio between them through the media relay. Owning both legs is
// what lets the PBX traverse NAT, and later play hold music, record
// voicemail and mix conferences.
package b2bua

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/media"
	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/JustSparx/SIPBXGO/internal/sipauth"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// AllowMethods is advertised in Allow headers.
const AllowMethods = "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE"

// Store is the persistence the engine needs.
type Store interface {
	GetExtension(ctx context.Context, number string) (*store.Extension, error)
	ListRegistrations(ctx context.Context, ext string) ([]*store.Registration, error)
	SaveCall(ctx context.Context, c *store.CallRecord) error
}

type Config struct {
	RingTimeout  time.Duration
	MediaTimeout time.Duration
	// HoldMusic plays to a caller put on hold; nil means silence.
	HoldMusic *media.Loop
}

type Engine struct {
	cfg    Config
	store  Store
	guard  *sipauth.Guard
	ports  *media.PortPool
	client *sipgo.Client
	log    *slog.Logger

	// Set by Bind once sockets are open.
	publicIP netip.Addr
	udpLaddr sip.Addr
	uaUDP    *sipgo.DialogUA
	uaTCP    *sipgo.DialogUA
	uaTLS    *sipgo.DialogUA

	mu    sync.Mutex
	byA   map[string]*Call // caller-leg dialog ID (PBX is UAS)
	byB   map[string]*Call // callee-leg dialog ID (PBX is UAC)
	calls map[string]*Call // active calls by Call.ID
}

func New(cfg Config, st Store, guard *sipauth.Guard, ports *media.PortPool, client *sipgo.Client, log *slog.Logger) *Engine {
	return &Engine{
		cfg: cfg, store: st, guard: guard, ports: ports, client: client, log: log,
		byA:   make(map[string]*Call),
		byB:   make(map[string]*Call),
		calls: make(map[string]*Call),
	}
}

// Bind supplies the addresses known only after the SIP sockets are open:
// the public IP written into Contact/SDP, and the local UDP listener, which
// outbound UDP requests must be sent from so they pass back through each
// phone's NAT mapping. tlsPort is 0 when TLS is off; tlsHost is the name on
// the certificate, used in TLS contacts so phones can verify it.
func (e *Engine) Bind(publicIP netip.Addr, udpPort, tcpPort, tlsPort int, tlsHost string, udpLaddr sip.Addr) {
	e.publicIP = publicIP.Unmap()
	e.udpLaddr = udpLaddr
	contact := func(port int, transport string) sip.ContactHeader {
		host := e.publicIP.String()
		if transport == "tls" && tlsHost != "" {
			host = tlsHost
		}
		uri := sip.Uri{Scheme: "sip", User: "sipbxgo", Host: host, Port: port}
		if transport != "" {
			uri.UriParams = sip.NewParams()
			uri.UriParams.Add("transport", transport)
		}
		return sip.ContactHeader{Address: uri}
	}
	e.uaUDP = &sipgo.DialogUA{Client: e.client, ContactHDR: contact(udpPort, ""), RewriteContact: true}
	e.uaTCP = &sipgo.DialogUA{Client: e.client, ContactHDR: contact(tcpPort, "tcp"), RewriteContact: true}
	if tlsPort > 0 {
		e.uaTLS = &sipgo.DialogUA{Client: e.client, ContactHDR: contact(tlsPort, "tls"), RewriteContact: true}
	}
}

func (e *Engine) uaFor(transport string) *sipgo.DialogUA {
	switch {
	case isTLS(transport) && e.uaTLS != nil:
		return e.uaTLS
	case strings.EqualFold(transport, "TCP"):
		return e.uaTCP
	}
	return e.uaUDP
}

// ActiveCalls returns a snapshot of calls in progress.
func (e *Engine) ActiveCalls() []*Call {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Call, 0, len(e.calls))
	for _, c := range e.calls {
		out = append(out, c)
	}
	return out
}

// HandleInvite handles new calls and re-INVITEs. For a new call it blocks
// until the call is answered (and ACKed) or has failed: sipgo ends the
// server transaction when the handler returns.
func (e *Engine) HandleInvite(req *sip.Request, tx sip.ServerTransaction) {
	if to := req.To(); to != nil && to.Params.Has("tag") {
		e.handleInDialog(req, tx)
		return
	}

	caller := e.guard.Authorize(req, tx)
	if caller == nil {
		return
	}
	ctx := context.Background()
	respond := func(code int, reason string) {
		tx.Respond(sip.NewResponseFromRequest(req, code, reason, nil))
	}
	if caller.RequireTLS && !isTLS(req.Transport()) {
		e.log.Warn("call refused: extension requires TLS", "caller", caller.Number, "transport", req.Transport())
		respond(403, "TLS Required")
		return
	}

	target := req.Recipient.User
	callee, err := e.store.GetExtension(ctx, target)
	switch {
	case errors.Is(err, store.ErrNotFound):
		respond(404, "Not Found")
		return
	case err != nil:
		e.log.Error("extension lookup", "error", err)
		respond(500, "Server Error")
		return
	case !callee.Enabled:
		respond(480, "Temporarily Unavailable")
		return
	case callee.Number == caller.Number:
		respond(486, "Busy Here")
		return
	}

	offer, err := sdp.Parse(req.Body())
	if err != nil {
		// Late-offer INVITEs (no SDP) are not supported yet.
		e.log.Warn("rejecting INVITE without usable SDP", "caller", caller.Number, "error", err)
		respond(488, "Not Acceptable Here")
		return
	}
	if caller.RequireTLS && !offer.Secure {
		e.log.Warn("call refused: extension requires encrypted audio", "caller", caller.Number)
		respond(488, "SRTP Required")
		return
	}

	regs, err := e.store.ListRegistrations(ctx, callee.Number)
	if err != nil {
		e.log.Error("registration lookup", "error", err)
		respond(500, "Server Error")
		return
	}
	if callee.RequireTLS {
		// Skip plain registrations left over from before TLS was required.
		kept := regs[:0]
		for _, r := range regs {
			if isTLS(r.Transport) {
				kept = append(kept, r)
			}
		}
		regs = kept
	}

	call := &Call{
		ID:         newCallID(),
		Caller:     caller.Number,
		CallerName: caller.Name,
		Callee:     callee.Number,
		Started:    time.Now(),
		e:          e,
		log:        e.log,
	}
	call.log = e.log.With("call", call.ID, "caller", call.Caller, "callee", call.Callee)

	if len(regs) == 0 {
		call.log.Info("call failed: callee not registered")
		respond(480, "Temporarily Unavailable")
		call.record(store.CallUnavailable, "system")
		return
	}

	respond(100, "Trying")
	aSession, err := e.uaFor(req.Transport()).ReadInvite(req, tx)
	if err != nil {
		call.log.Error("read invite", "error", err)
		respond(500, "Server Error")
		return
	}
	call.a = aSession
	call.aSignalIP = sipauth.SourceIP(req)

	call.relay, err = media.NewRelay(e.ports, call.log)
	if err != nil {
		call.log.Error("media relay", "error", err)
		aSession.Respond(503, "Service Unavailable", nil)
		call.record(store.CallFailed, "system")
		return
	}
	call.relay.SetRemote(media.Caller, offer, call.aSignalIP)
	if _, err := call.acceptOffer(media.Caller, offer); err != nil {
		call.log.Warn("caller's SRTP offer unusable", "error", err)
		call.fail(488, "Not Acceptable Here", store.CallFailed, "system")
		return
	}
	call.relay.Start()

	call.log.Info("call started", "phones", len(regs))
	call.setup(req.Body(), regs)
}

// register makes an established call findable by its dialogs.
func (e *Engine) register(c *Call) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.byA[c.a.ID] = c
	e.byB[c.b.ID] = c
	e.calls[c.ID] = c
}

func (e *Engine) unregister(c *Call) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.a != nil {
		delete(e.byA, c.a.ID)
	}
	if c.b != nil {
		delete(e.byB, c.b.ID)
	}
	delete(e.calls, c.ID)
}

// lookup finds the call an in-dialog request belongs to and which side sent it.
func (e *Engine) lookup(req *sip.Request) (*Call, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id, err := sip.DialogIDFromRequestUAS(req); err == nil {
		if c, ok := e.byA[id]; ok {
			return c, media.Caller
		}
	}
	if id, err := sip.DialogIDFromRequestUAC(req); err == nil {
		if c, ok := e.byB[id]; ok {
			return c, media.Callee
		}
	}
	return nil, -1
}

// HandleAck confirms an answered call. ACKs for re-INVITEs need no action:
// the PBX already ACKed the other phone itself.
func (e *Engine) HandleAck(req *sip.Request, tx sip.ServerTransaction) {
	if c, side := e.lookup(req); c != nil && side == media.Caller {
		c.a.ReadAck(req, tx)
	}
}

// HandleBye hangs up a call from either side.
func (e *Engine) HandleBye(req *sip.Request, tx sip.ServerTransaction) {
	c, side := e.lookup(req)
	if c == nil {
		tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	var err error
	if side == media.Caller {
		err = c.a.ReadBye(req, tx)
		c.hangup("caller")
	} else {
		err = c.b.ReadBye(req, tx)
		c.hangup("callee")
	}
	if err != nil {
		c.log.Debug("read bye", "error", err)
	}
}

// HandleCancel answers CANCELs that matched no pending INVITE (sipgo
// handles the ones that do).
func (e *Engine) HandleCancel(req *sip.Request, tx sip.ServerTransaction) {
	tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
}

// HandleInDialog forwards INFO (DTMF), UPDATE and similar requests to the
// other phone in the call.
func (e *Engine) HandleInDialog(req *sip.Request, tx sip.ServerTransaction) {
	e.handleInDialog(req, tx)
}

// HandleRefer rejects call transfer until it is implemented.
func (e *Engine) HandleRefer(req *sip.Request, tx sip.ServerTransaction) {
	if c, _ := e.lookup(req); c == nil {
		tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	tx.Respond(sip.NewResponseFromRequest(req, 501, "Not Implemented", nil))
}

// Monitor hangs up calls whose media has gone silent, e.g. a phone that lost
// power or network mid-call. Runs until ctx is cancelled.
func (e *Engine) Monitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, c := range e.ActiveCalls() {
				if idle := c.relay.Idle(); idle > e.cfg.MediaTimeout {
					c.log.Warn("no media, hanging up", "idle", idle.Round(time.Second))
					c.hangup("system")
				}
			}
		}
	}
}

// HangupAll ends every active call (used at shutdown).
func (e *Engine) HangupAll() {
	var wg sync.WaitGroup
	for _, c := range e.ActiveCalls() {
		wg.Add(1)
		go func() { defer wg.Done(); c.hangup("system") }()
	}
	wg.Wait()
}

func newCallID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
