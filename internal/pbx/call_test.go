package pbx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
)

// callPhone is a minimal SIP phone for end-to-end call tests: it registers,
// places and answers calls, and has an RTP socket for checking media.
type callPhone struct {
	t        *testing.T
	ext      string
	pbx      string
	client   *sipgo.Client
	contact  sip.ContactHeader
	servers  *sipgo.DialogServerCache
	clients  *sipgo.DialogClientCache
	rtp      *net.UDPConn
	behavior string // "answer", "busy", "ring"

	transport string      // "UDP" or "TLS"
	key       *sdp.Crypto // phone's SRTP key; nil for plain RTP

	incoming  chan *sipgo.DialogServerSession // ringing calls
	answered  chan *sipgo.DialogServerSession // calls this phone answered and got ACK for
	reinvites chan *sip.Request
	byes      chan struct{}
	cancelled chan struct{}
}

func newCallPhone(t *testing.T, pbx, ext, behavior string) *callPhone {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("TestPhone/" + ext))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	// Send from the listening socket, like a real phone.
	client, err := sipgo.NewClient(ua, sipgo.WithClientConnectionAddr(addr.String()))
	if err != nil {
		t.Fatal(err)
	}
	rtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &callPhone{
		t: t, ext: ext, pbx: pbx, client: client, rtp: rtp, behavior: behavior, transport: "UDP",
		contact:   sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: ext, Host: "127.0.0.1", Port: addr.Port}},
		incoming:  make(chan *sipgo.DialogServerSession, 4),
		answered:  make(chan *sipgo.DialogServerSession, 4),
		reinvites: make(chan *sip.Request, 4),
		byes:      make(chan struct{}, 4),
		cancelled: make(chan struct{}, 4),
	}
	p.servers = sipgo.NewDialogServerCache(client, p.contact)
	p.clients = sipgo.NewDialogClientCache(client, p.contact)

	srv.OnInvite(p.onInvite)
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { p.servers.ReadAck(req, tx) })
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if p.servers.ReadBye(req, tx) == nil || p.clients.ReadBye(req, tx) == nil {
			p.byes <- struct{}{}
			return
		}
		tx.Respond(sip.NewResponseFromRequest(req, 481, "No Dialog", nil))
	})
	go srv.ServeUDP(conn)
	// ServeUDP registers the socket asynchronously; until it has, the client
	// would try to bind the same address itself and fail.
	for i := 0; ; i++ {
		if c, _ := ua.TransportLayer().GetConnection("udp", addr.String()); c != nil {
			break
		}
		if i == 100 {
			t.Fatal("phone socket never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { srv.Close(); client.Close(); ua.Close(); conn.Close(); rtp.Close() })
	return p
}

// offer is the phone's SDP; like a phone behind NAT it shows a private IP.
// SRTP phones use RTP/SAVP with their key.
func (p *callPhone) offer(extra string) []byte {
	port := p.rtp.LocalAddr().(*net.UDPAddr).Port
	proto, crypto := "RTP/AVP", ""
	if p.key != nil {
		proto, crypto = "RTP/SAVP", "a="+p.key.String()+"\r\n"
	}
	return []byte("v=0\r\no=- 1 1 IN IP4 192.168.1.50\r\ns=-\r\nc=IN IP4 192.168.1.50\r\nt=0 0\r\n" +
		fmt.Sprintf("m=audio %d %s 0 101\r\n", port, proto) +
		"a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n" + crypto + extra)
}

func (p *callPhone) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	if to := req.To(); to != nil && to.Params.Has("tag") { // re-INVITE
		p.reinvites <- req
		res := sip.NewSDPResponseFromRequest(req, p.offer("a=recvonly\r\n"))
		tx.Respond(res)
		return
	}
	ds, err := p.servers.ReadInvite(req, tx)
	if err != nil {
		p.t.Errorf("%s: read invite: %v", p.ext, err)
		return
	}
	switch p.behavior {
	case "busy":
		ds.Respond(486, "Busy Here", nil)
	case "ring":
		ds.Respond(180, "Ringing", nil)
		p.incoming <- ds
		<-ds.Context().Done()
		p.cancelled <- struct{}{}
		select { // consume the ACK for sipgo's automatic 487
		case <-tx.Acks():
		case <-tx.Done():
		}
	default:
		ds.Respond(180, "Ringing", nil)
		time.Sleep(50 * time.Millisecond)
		p.incoming <- ds
		if err := ds.RespondSDP(p.offer("")); err != nil {
			p.t.Errorf("%s: answer: %v", p.ext, err)
			return
		}
		// Hand the dialog over only now: the channel send orders the
		// session's writes before the test's use of it (race detector).
		p.answered <- ds
	}
}

func (p *callPhone) register(pass string) {
	p.t.Helper()
	var uri sip.Uri
	sip.ParseUri(fmt.Sprintf("sip:%s@%s", p.ext, p.pbx), &uri)
	req := sip.NewRequest(sip.REGISTER, uri)
	req.AppendHeader(&p.contact)
	req.AppendHeader(sip.NewHeader("Expires", "120"))
	req.SetTransport(p.transport)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.client.Do(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err == nil && res.StatusCode == 401 {
		res, err = p.client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.ext, Password: pass})
	}
	if err != nil || res.StatusCode != 200 {
		p.t.Fatalf("%s register: %v %v", p.ext, res, err)
	}
}

// call dials target and waits for the final answer.
func (p *callPhone) call(ctx context.Context, target, pass string) (*sipgo.DialogClientSession, error) {
	var uri sip.Uri
	sip.ParseUri(fmt.Sprintf("sip:%s@%s;transport=%s", target, p.pbx, strings.ToLower(p.transport)), &uri)
	from := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: p.ext, Host: "127.0.0.1"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(10))
	dc, err := p.clients.Invite(ctx, uri, p.offer(""), from, sip.NewHeader("Content-Type", "application/sdp"))
	if err != nil {
		return nil, err
	}
	if err := dc.WaitAnswer(ctx, sipgo.AnswerOptions{Username: p.ext, Password: pass}); err != nil {
		return dc, err
	}
	return dc, dc.Ack(ctx)
}

// relayPort extracts the PBX relay port from SDP the phone received.
func relayPort(t *testing.T, body []byte) int {
	t.Helper()
	info, err := sdp.Parse(body)
	if err != nil {
		t.Fatalf("bad SDP from PBX: %v\n%s", err, body)
	}
	if info.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("SDP not rewritten to PBX address:\n%s", body)
	}
	return info.Port
}

func (p *callPhone) sendRTP(port int, payload string) {
	p.rtp.WriteToUDP([]byte(payload), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func (p *callPhone) recvRTP() string {
	p.rtp.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 200)
	n, _, err := p.rtp.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func lastCall(t *testing.T, st *store.Store) *store.CallRecord {
	t.Helper()
	// The record is written just after the SIP exchange finishes.
	for i := 0; i < 50; i++ {
		if calls, _ := st.ListCalls(context.Background(), "", 1, 0); len(calls) == 1 {
			return calls[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no call record written")
	return nil
}

func TestCallAnswerMediaHoldHangup(t *testing.T) {
	srv, st := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "102", "pw101")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	ds := wait(t, b.incoming, "incoming call at 102")

	// Caller ID is the authenticated extension.
	if from := ds.InviteRequest.From(); from.Address.User != "101" {
		t.Errorf("callee saw caller %q, want 101", from.Address.User)
	}
	// Both phones were given the relay, not each other's (private) address.
	portA := relayPort(t, dc.InviteResponse.Body())
	portB := relayPort(t, ds.InviteRequest.Body())
	if portA == portB {
		t.Fatal("caller and callee share a relay port")
	}

	// Audio flows both ways through the relay.
	b.sendRTP(portB, "hello from 102")
	if got := a.recvRTP(); got != "hello from 102" {
		t.Fatalf("caller got %q", got)
	}
	a.sendRTP(portA, "hello from 101")
	if got := b.recvRTP(); got != "hello from 101" {
		t.Fatalf("callee got %q", got)
	}
	if n := len(srv.Engine().ActiveCalls()); n != 1 {
		t.Fatalf("active calls = %d, want 1", n)
	}

	// Hold: the PBX answers the caller's re-INVITE itself and plays music
	// to the callee, whose session is left alone.
	res := reinvite(t, ctx, dc, a.offer("a=sendonly\r\n"))
	if !strings.Contains(string(res.Body()), "a=recvonly") || relayPort(t, res.Body()) != portA {
		t.Errorf("bad hold answer to caller:\n%s", res.Body())
	}
	expectMusic(t, b)
	select {
	case r := <-b.reinvites:
		t.Fatalf("hold was passed on to the callee:\n%s", r.Body())
	default:
	}
	if calls := srv.Engine().ActiveCalls(); len(calls) != 1 || !calls[0].OnHold() {
		t.Fatal("call not reported on hold")
	}

	// Resume: music stops and audio flows again.
	res = reinvite(t, ctx, dc, a.offer("a=sendrecv\r\n"))
	if !strings.Contains(string(res.Body()), "a=sendrecv") {
		t.Errorf("bad resume answer:\n%s", res.Body())
	}
	drainRTP(b)
	a.sendRTP(portA, "back again")
	if got := b.recvRTP(); got != "back again" {
		t.Fatalf("after resume callee got %q", got)
	}

	// Caller hangs up; callee gets BYE.
	if err := dc.Bye(ctx); err != nil {
		t.Fatalf("bye: %v", err)
	}
	wait(t, b.byes, "BYE at callee")
	rec := lastCall(t, st)
	if rec.Status != store.CallAnswered || rec.HangupBy != "caller" || rec.AnsweredAt.IsZero() {
		t.Errorf("call record: %+v", rec)
	}
	if n := len(srv.Engine().ActiveCalls()); n != 0 {
		t.Errorf("active calls after hangup = %d", n)
	}
}

func TestCalleeHangsUp(t *testing.T) {
	srv, st := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.call(ctx, "102", "pw101"); err != nil {
		t.Fatal(err)
	}
	ds := wait(t, b.answered, "callee answered")
	if err := ds.Bye(ctx); err != nil {
		t.Fatalf("callee bye: %v", err)
	}
	wait(t, a.byes, "BYE at caller")
	if rec := lastCall(t, st); rec.HangupBy != "callee" {
		t.Errorf("hangup_by = %q, want callee", rec.HangupBy)
	}
}

func TestCallBusy(t *testing.T) {
	srv, st := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "busy")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := a.call(ctx, "102", "pw101")
	var de *sipgo.ErrDialogResponse
	if !errors.As(err, &de) || de.Res.StatusCode != 486 {
		t.Fatalf("got %v, want 486", err)
	}
	if rec := lastCall(t, st); rec.Status != store.CallBusy {
		t.Errorf("status = %q, want busy", rec.Status)
	}
}

func TestCallerCancelsWhileRinging(t *testing.T) {
	srv, st := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "ring")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := a.call(ctx, "102", "pw101"); errc <- err }()
	wait(t, b.incoming, "ringing at callee")
	cancel() // caller hangs up before answer: sends CANCEL
	wait(t, b.cancelled, "CANCEL to reach callee")
	<-errc
	if rec := lastCall(t, st); rec.Status != store.CallCancelled || rec.HangupBy != "caller" {
		t.Errorf("call record: %+v", rec)
	}
}

func TestCallFailures(t *testing.T) {
	srv, _ := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	a.register("pw101")

	cases := []struct {
		name, target, pass string
		want               int
	}{
		{"callee not registered", "102", "pw101", 480},
		{"unknown extension", "555", "pw101", 404},
		{"calling yourself", "101", "pw101", 486},
		{"wrong password", "102", "wrong", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := a.call(ctx, tc.target, tc.pass)
			var de *sipgo.ErrDialogResponse
			if !errors.As(err, &de) || de.Res.StatusCode != tc.want {
				t.Fatalf("got %v, want %d", err, tc.want)
			}
		})
	}
}

func TestForkingFirstAnswerWins(t *testing.T) {
	srv, st := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	desk := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	soft := newCallPhone(t, srv.UDPAddr(), "102", "ring") // same extension, never answers
	a.register("pw101")
	desk.register("pw102")
	soft.register("pw102")
	if regs, _ := st.ListRegistrations(context.Background(), "102"); len(regs) != 2 {
		t.Fatalf("want 2 bindings for 102, got %d", len(regs))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "102", "pw101")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	wait(t, soft.incoming, "second phone ringing")
	wait(t, desk.incoming, "desk phone answering")
	wait(t, soft.cancelled, "CANCEL to the phone that lost")

	dc.Bye(ctx)
	wait(t, desk.byes, "BYE at desk phone")
	if rec := lastCall(t, st); rec.Status != store.CallAnswered {
		t.Errorf("status = %q", rec.Status)
	}
}

func TestCalleePutsCallOnHold(t *testing.T) {
	srv, _ := startPBX(t, 100)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "102", "pw101")
	if err != nil {
		t.Fatal(err)
	}
	ds := wait(t, b.answered, "callee answered")

	reinv := sip.NewRequest(sip.INVITE, ds.InviteRequest.Contact().Address)
	reinv.SetBody(b.offer("a=inactive\r\n"))
	reinv.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res, err := ds.Do(ctx, reinv)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("callee hold re-INVITE: %v %v", res, err)
	}
	if !strings.Contains(string(res.Body()), "a=inactive") {
		t.Errorf("callee got bad hold answer:\n%s", res.Body())
	}
	expectMusic(t, a) // the caller is the one waiting now
	dc.Bye(ctx)
	wait(t, b.byes, "BYE at callee")
}

// reinvite sends an in-dialog INVITE with body and ACKs the 200.
func reinvite(t *testing.T, ctx context.Context, dc *sipgo.DialogClientSession, body []byte) *sip.Response {
	t.Helper()
	req := sip.NewRequest(sip.INVITE, dc.InviteResponse.Contact().Address)
	req.SetBody(body)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res, err := dc.Do(ctx, req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("re-INVITE: %v %v", res, err)
	}
	ack := sip.NewRequest(sip.ACK, dc.InviteResponse.Contact().Address)
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: res.CSeq().SeqNo, MethodName: sip.ACK})
	dc.WriteRequest(ack)
	return res
}

// expectMusic checks that the phone is receiving hold music: a steady
// stream of 20 ms G.711 packets.
func expectMusic(t *testing.T, p *callPhone) {
	t.Helper()
	for i := 0; i < 5; i++ {
		raw := p.recvRTP()
		if raw == "" {
			t.Fatalf("%s: no hold music", p.ext)
		}
		var pkt rtp.Packet
		if err := pkt.Unmarshal([]byte(raw)); err != nil {
			t.Fatalf("%s: hold music is not RTP: %v", p.ext, err)
		}
		if pkt.PayloadType != 0 || len(pkt.Payload) != 160 {
			t.Fatalf("%s: unexpected hold music packet: pt=%d len=%d", p.ext, pkt.PayloadType, len(pkt.Payload))
		}
	}
}

// drainRTP discards packets already queued (e.g. the tail of hold music).
func drainRTP(p *callPhone) {
	buf := make([]byte, 2048)
	for {
		p.rtp.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
		if _, _, err := p.rtp.ReadFromUDP(buf); err != nil {
			return
		}
	}
}
