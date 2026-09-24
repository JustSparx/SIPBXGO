package b2bua

import (
	"context"
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

// Call is one extension-to-extension call: the caller's dialog with the
// PBX (A leg), the PBX's dialog with the callee (B leg), and the media
// relay between them.
type Call struct {
	ID         string
	Caller     string
	CallerName string
	Callee     string
	Started    time.Time
	Answered   time.Time

	e     *Engine
	log   *slog.Logger
	relay *media.Relay

	a         *sipgo.DialogServerSession
	aSignalIP netip.Addr
	b         *sipgo.DialogClientSession

	mu         sync.Mutex
	ringing    bool      // 180 sent to caller
	earlyMedia bool      // 183 with SDP sent to caller
	reinvite   bool      // re-INVITE in progress (another one gets 491)
	sdpTo      [2][]byte // last SDP the PBX sent to each side
	endOnce    sync.Once
}

// leg is what both dialog session types offer for in-dialog requests.
type leg interface {
	Do(ctx context.Context, req *sip.Request) (*sip.Response, error)
	WriteRequest(req *sip.Request) error
}

func (c *Call) session(side int) leg {
	if side == media.Caller {
		return c.a
	}
	return c.b
}

// target is the Request-URI for in-dialog requests to a side (its Contact).
// Where the request is actually sent is the phone's real source address;
// sipgo's RewriteContact mode handles that.
func (c *Call) target(side int) sip.Uri {
	if side == media.Caller {
		return c.a.InviteRequest.Contact().Address
	}
	return c.b.InviteResponse.Contact().Address
}

type forkResult struct {
	dc  *sipgo.DialogClientSession
	reg *store.Registration
	err error
}

// setup rings every registered phone of the callee, relays ringing to the
// caller, and connects the first phone to answer. It returns once the call
// is answered and ACKed, or has failed.
func (c *Call) setup(offer []byte, regs []*store.Registration) {
	e := c.e
	offerB, err := sdp.Rewrite(offer, e.publicIP, c.relay.Legs[media.Callee].Port)
	if err != nil {
		c.fail(488, "Not Acceptable Here", store.CallFailed, "system")
		return
	}
	c.sdpTo[media.Callee] = offerB

	ringCtx, stopRinging := context.WithTimeout(c.a.Context(), e.cfg.RingTimeout)
	defer stopRinging()

	results := make(chan forkResult, len(regs))
	forks := 0
	for _, reg := range regs {
		inv, err := c.buildInvite(reg, offerB)
		if err != nil {
			c.log.Warn("bad registration contact", "contact", reg.Contact, "error", err)
			continue
		}
		dc, err := e.uaFor(reg.Transport).WriteInvite(ringCtx, inv)
		if err != nil {
			c.log.Warn("could not reach phone", "contact", reg.Contact, "source", reg.Source, "error", err)
			continue
		}
		forks++
		go func() {
			err := dc.WaitAnswer(ringCtx, sipgo.AnswerOptions{
				OnResponse: func(r *sip.Response) error { c.onProvisional(r); return nil },
			})
			results <- forkResult{dc: dc, reg: reg, err: err}
		}()
	}
	if forks == 0 {
		c.fail(480, "Temporarily Unavailable", store.CallUnavailable, "system")
		return
	}

	// First phone to answer wins. Losing phones are cancelled by stopRinging
	// and finish in the background.
	var winner *forkResult
	var codes []int
	for i := 0; i < forks && winner == nil; i++ {
		r := <-results
		if r.err == nil {
			winner = &r
			stopRinging()
			go c.dropLateAnswers(results, forks-i-1)
			break
		}
		var de *sipgo.ErrDialogResponse
		if errors.As(r.err, &de) {
			codes = append(codes, de.Res.StatusCode)
		}
		c.log.Debug("phone did not answer", "contact", r.reg.Contact, "error", r.err)
	}

	if winner == nil {
		switch {
		case c.a.Context().Err() != nil:
			// Caller hung up while ringing; sipgo already sent 487.
			c.fail(487, "Request Terminated", store.CallCancelled, "caller")
		case errors.Is(ringCtx.Err(), context.DeadlineExceeded):
			c.fail(480, "No Answer", store.CallNoAnswer, "system")
		case contains(codes, 486) || contains(codes, 600):
			c.fail(486, "Busy Here", store.CallBusy, "callee")
		case contains(codes, 603):
			c.fail(603, "Decline", store.CallBusy, "callee")
		default:
			c.fail(480, "Temporarily Unavailable", store.CallUnavailable, "system")
		}
		return
	}

	c.connect(winner.dc)
}

// connect finishes a call once a callee phone has answered.
func (c *Call) connect(dc *sipgo.DialogClientSession) {
	e := c.e
	c.b = dc
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := dc.Ack(ctx); err != nil {
		c.log.Warn("ack to callee failed", "error", err)
	}
	answer := dc.InviteResponse.Body()
	info, err := sdp.Parse(answer)
	if err != nil {
		c.log.Warn("callee answered without usable SDP", "error", err)
		dc.Bye(ctx)
		c.fail(488, "Not Acceptable Here", store.CallFailed, "system")
		return
	}
	c.relay.SetRemote(media.Callee, info, responseIP(dc.InviteResponse))
	answerA, err := sdp.Rewrite(answer, e.publicIP, c.relay.Legs[media.Caller].Port)
	if err != nil {
		dc.Bye(ctx)
		c.fail(488, "Not Acceptable Here", store.CallFailed, "system")
		return
	}
	c.sdpTo[media.Caller] = answerA
	c.Answered = time.Now()
	e.register(c)
	c.log.Info("call answered", "phone", dc.InviteResponse.Source())

	// Blocks until the caller ACKs (HandleAck) or gives up.
	err = c.a.Respond(200, "OK", answerA,
		sip.NewHeader("Content-Type", "application/sdp"),
		sip.NewHeader("Allow", AllowMethods))
	if err != nil {
		c.log.Warn("caller did not confirm answer", "error", err)
		c.hangup("system")
	}
}

// dropLateAnswers hangs up phones that answered after another phone won.
func (c *Call) dropLateAnswers(results <-chan forkResult, n int) {
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r.dc.Ack(ctx)
		r.dc.Bye(ctx)
		cancel()
	}
}

// onProvisional relays ringing (and early media) from callee phones.
func (c *Call) onProvisional(r *sip.Response) {
	if !r.IsProvisional() || r.StatusCode == 100 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.StatusCode == 183 && len(r.Body()) > 0 && !c.earlyMedia {
		if info, err := sdp.Parse(r.Body()); err == nil {
			c.relay.SetRemote(media.Callee, info, responseIP(r))
			if body, err := sdp.Rewrite(r.Body(), c.e.publicIP, c.relay.Legs[media.Caller].Port); err == nil {
				c.earlyMedia = true
				c.a.Respond(183, "Session Progress", body, sip.NewHeader("Content-Type", "application/sdp"))
				return
			}
		}
	}
	if !c.ringing && !c.earlyMedia {
		c.ringing = true
		c.a.Respond(180, "Ringing", nil)
	}
}

func (c *Call) buildInvite(reg *store.Registration, body []byte) (*sip.Request, error) {
	var recipient sip.Uri
	if err := sip.ParseUri(reg.Contact, &recipient); err != nil {
		return nil, err
	}
	host := c.e.publicIP.String()
	inv := sip.NewRequest(sip.INVITE, recipient)

	from := &sip.FromHeader{
		DisplayName: displayName(c.CallerName),
		Address:     sip.Uri{Scheme: "sip", User: c.Caller, Host: host},
		Params:      sip.NewParams(),
	}
	from.Params.Add("tag", sip.GenerateTagN(16))
	to := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: c.Callee, Host: host}, Params: sip.NewParams()}
	contact := c.e.uaFor(reg.Transport).ContactHDR

	inv.AppendHeader(from)
	inv.AppendHeader(to)
	inv.AppendHeader(&contact)
	inv.AppendHeader(sip.NewHeader("Allow", AllowMethods))
	inv.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	inv.SetBody(body)

	transport := strings.ToUpper(reg.Transport)
	inv.SetTransport(transport)
	inv.SetDestination(reg.Source)
	if transport == "UDP" {
		// Send from the port the phone registered to, or its NAT drops us.
		c.e.udpLaddr.Copy(&inv.Laddr)
	}
	return inv, nil
}

// fail ends a call that never connected.
func (c *Call) fail(code int, reason, status, by string) {
	if err := c.a.Respond(code, reason, nil); err != nil {
		c.log.Debug("final response not sent", "code", code, "error", err)
	}
	c.relay.Close()
	c.record(status, by)
}

// hangup ends a connected call, sending BYE to whichever sides did not
// hang up themselves. by is "caller", "callee" or "system".
func (c *Call) hangup(by string) {
	c.endOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		if by != "caller" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.a.Bye(ctx); err != nil {
					c.log.Debug("bye to caller", "error", err)
				}
			}()
		}
		if by != "callee" && c.b != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.b.Bye(ctx); err != nil {
					c.log.Debug("bye to callee", "error", err)
				}
			}()
		}
		wg.Wait()
		c.e.unregister(c)
		c.relay.Close()
		c.record(store.CallAnswered, by)
	})
}

func (c *Call) record(status, by string) {
	rec := &store.CallRecord{
		ID: c.ID, Caller: c.Caller, Callee: c.Callee, Status: status, HangupBy: by,
		StartedAt: c.Started, AnsweredAt: c.Answered, EndedAt: time.Now(),
	}
	if err := c.e.store.SaveCall(context.Background(), rec); err != nil {
		c.log.Error("save call record", "error", err)
	}
	attrs := []any{"status", status, "hangup_by", by}
	if !c.Answered.IsZero() {
		attrs = append(attrs, "duration", rec.Duration().Round(time.Second))
	}
	if c.relay != nil {
		attrs = append(attrs, "media", c.relay.String())
	}
	c.log.Info("call ended", attrs...)
}

// forward relays an in-dialog request (re-INVITE for hold/resume, UPDATE,
// INFO for DTMF...) from one phone to the other and relays the answer back,
// rewriting SDP so media keeps flowing through the relay.
func (c *Call) forward(req *sip.Request, tx sip.ServerTransaction, from int) {
	to := 1 - from
	isInvite := req.IsInvite()
	if isInvite {
		c.mu.Lock()
		busy := c.reinvite
		c.reinvite = true
		c.mu.Unlock()
		if busy {
			tx.Respond(sip.NewResponseFromRequest(req, 491, "Request Pending", nil))
			return
		}
		defer func() { c.mu.Lock(); c.reinvite = false; c.mu.Unlock() }()
		tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	}

	body, ctype := req.Body(), contentType(req)
	if isInvite && len(body) == 0 {
		// Offerless re-INVITE (typically a session refresh): media is
		// unchanged, so answer with the SDP this phone already has.
		c.respond(req, tx, 200, "OK", c.sdpTo[from])
		return
	}
	if ctype == "application/sdp" && len(body) > 0 {
		info, err := sdp.Parse(body)
		if err != nil {
			tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		c.relay.SetRemote(from, info, sipauth.SourceIP(req))
		if body, err = sdp.Rewrite(body, c.e.publicIP, c.relay.Legs[to].Port); err != nil {
			tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		if isInvite {
			c.sdpTo[to] = body
		}
	}

	fwd := sip.NewRequest(req.Method, c.target(to))
	if len(body) > 0 {
		fwd.SetBody(body)
		fwd.AppendHeader(sip.NewHeader("Content-Type", ctype))
	}
	for _, name := range []string{"Info-Package", "Event"} {
		if h := req.GetHeader(name); h != nil {
			fwd.AppendHeader(sip.NewHeader(name, h.Value()))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	res, err := c.session(to).Do(ctx, fwd)
	if err != nil {
		c.log.Warn("in-dialog request not answered", "method", req.Method, "error", err)
		tx.Respond(sip.NewResponseFromRequest(req, 408, "Request Timeout", nil))
		return
	}
	if isInvite && res.IsSuccess() {
		ack := sip.NewRequest(sip.ACK, c.target(to))
		ack.AppendHeader(&sip.CSeqHeader{SeqNo: res.CSeq().SeqNo, MethodName: sip.ACK})
		if err := c.session(to).WriteRequest(ack); err != nil {
			c.log.Warn("ack for re-INVITE failed", "error", err)
		}
	}

	resBody := res.Body()
	if len(resBody) > 0 && contentType(res) == "application/sdp" {
		if info, err := sdp.Parse(resBody); err == nil {
			c.relay.SetRemote(to, info, responseIP(res))
		}
		if resBody, err = sdp.Rewrite(resBody, c.e.publicIP, c.relay.Legs[from].Port); err != nil {
			tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		if isInvite {
			c.sdpTo[from] = resBody
		}
	}
	if isInvite && res.IsSuccess() && len(resBody) > 0 {
		c.log.Info("call media updated", "by", sideName(from), "hold", holdState(req.Body()))
	}
	c.respond(req, tx, res.StatusCode, res.Reason, resBody)
}

// respond answers an in-dialog request, adding SDP and Contact as needed.
func (c *Call) respond(req *sip.Request, tx sip.ServerTransaction, code int, reason string, body []byte) {
	res := sip.NewResponseFromRequest(req, code, reason, body)
	if len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	}
	if req.IsInvite() && code >= 200 && code < 300 {
		contact := c.e.uaFor(req.Transport()).ContactHDR
		res.AppendHeader(&contact)
	}
	tx.Respond(res)
}

func (e *Engine) handleInDialog(req *sip.Request, tx sip.ServerTransaction) {
	c, side := e.lookup(req)
	if c == nil {
		tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))
		return
	}
	c.forward(req, tx, side)
}

func contentType(m interface{ ContentType() *sip.ContentTypeHeader }) string {
	if h := m.ContentType(); h != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(h.Value(), ";", 2)[0]))
	}
	return ""
}

func responseIP(r *sip.Response) netip.Addr {
	ap, err := netip.ParseAddrPort(r.Source())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// displayName strips characters that would break a quoted SIP display name.
func displayName(s string) string {
	return strings.NewReplacer(`"`, "", `\`, "", "\r", "", "\n", "").Replace(s)
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

func sideName(side int) string {
	if side == media.Caller {
		return "caller"
	}
	return "callee"
}

func holdState(body []byte) bool {
	info, err := sdp.Parse(body)
	return err == nil && info.OnHold()
}
