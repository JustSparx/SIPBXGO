package pbx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/JustSparx/SIPBXGO/internal/tlscert"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

const testCertName = "pbx.test"

// startTLSPBX starts a PBX with SIP over TLS using a throwaway certificate
// and returns the CA pool phones need to trust it.
func startTLSPBX(t *testing.T) (*Server, *store.Store, *x509.CertPool) {
	t.Helper()
	cert, err := tlscert.SelfSigned(testCertName)
	if err != nil {
		t.Fatal(err)
	}
	srv, st := startPBX(t, 100, func(s *Server) { s.UseCertificate(tlscert.Static(cert, "test")) })
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	return srv, st, roots
}

// newTLSPhone is a phone that registers over TLS and uses SRTP. Like a real
// phone behind NAT it only has its outbound TLS connection; the PBX sends
// calls back down it.
func newTLSPhone(t *testing.T, srv *Server, roots *x509.CertPool, ext, behavior string) *callPhone {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("TestTLSPhone/"+ext),
		sipgo.WithUserAgenTLSConfig(&tls.Config{RootCAs: roots, ServerName: testCertName}))
	if err != nil {
		t.Fatal(err)
	}
	phoneSrv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	rtpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	key, err := sdp.NewCrypto(1, sdp.SuiteAES80)
	if err != nil {
		t.Fatal(err)
	}
	contact := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: ext, Host: "127.0.0.1", Port: 5061, UriParams: sip.NewParams()}}
	contact.Address.UriParams.Add("transport", "tls")
	p := &callPhone{
		t: t, ext: ext, pbx: fmt.Sprintf("127.0.0.1:%d", srv.TLSPort()), client: client, rtp: rtpConn,
		behavior: behavior, transport: "TLS", key: key, contact: contact,
		incoming:  make(chan *sipgo.DialogServerSession, 4),
		answered:  make(chan *sipgo.DialogServerSession, 4),
		reinvites: make(chan *sip.Request, 4),
		byes:      make(chan struct{}, 4),
		cancelled: make(chan struct{}, 4),
	}
	p.servers = sipgo.NewDialogServerCache(client, p.contact)
	p.clients = sipgo.NewDialogClientCache(client, p.contact)
	phoneSrv.OnInvite(p.onInvite)
	phoneSrv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { p.servers.ReadAck(req, tx) })
	phoneSrv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if p.servers.ReadBye(req, tx) == nil || p.clients.ReadBye(req, tx) == nil {
			p.byes <- struct{}{}
			return
		}
		tx.Respond(sip.NewResponseFromRequest(req, 481, "No Dialog", nil))
	})
	t.Cleanup(func() { phoneSrv.Close(); client.Close(); ua.Close(); rtpConn.Close() })
	return p
}

// pbxKey is the PBX's SRTP key for a phone, from SDP the phone received.
func pbxKey(t *testing.T, body []byte) *sdp.Crypto {
	t.Helper()
	info, err := sdp.Parse(body)
	if err != nil || !info.Secure || len(info.Cryptos) != 1 {
		t.Fatalf("expected SRTP SDP with one key from the PBX:\n%s", body)
	}
	return info.Cryptos[0]
}

func srtpCtx(t *testing.T, c *sdp.Crypto) *srtp.Context {
	t.Helper()
	x, err := srtp.CreateContext(c.Key[:16], c.Key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func rtpBytes(t *testing.T, payload string) []byte {
	t.Helper()
	b, err := (&rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: 1, SSRC: 42}, Payload: []byte(payload)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rtpPayload(t *testing.T, b []byte) string {
	t.Helper()
	var p rtp.Packet
	if err := p.Unmarshal(b); err != nil {
		t.Fatalf("not an RTP packet: %v", err)
	}
	return string(p.Payload)
}

// sendSRTP encrypts payload with the phone's own key and sends it.
func (p *callPhone) sendSRTP(port int, payload string) {
	enc, err := srtpCtx(p.t, p.key).EncryptRTP(nil, rtpBytes(p.t, payload), nil)
	if err != nil {
		p.t.Fatal(err)
	}
	p.rtp.WriteToUDP(enc, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

// recvSRTP receives a packet and decrypts it with the PBX's key.
func (p *callPhone) recvSRTP(key *sdp.Crypto) string {
	raw := p.recvRTP()
	if raw == "" {
		return ""
	}
	dec, err := srtpCtx(p.t, key).DecryptRTP(nil, []byte(raw), nil)
	if err != nil {
		p.t.Errorf("%s: SRTP decrypt failed: %v", p.ext, err)
		return ""
	}
	return rtpPayload(p.t, dec)
}

func keyB64(c *sdp.Crypto) string { return base64.StdEncoding.EncodeToString(c.Key) }

func TestEncryptedCallOverTLS(t *testing.T) {
	srv, st, roots := startTLSPBX(t)
	a := newTLSPhone(t, srv, roots, "101", "answer")
	b := newTLSPhone(t, srv, roots, "102", "answer")
	a.register("pw101")
	b.register("pw102")
	if regs, _ := st.ListRegistrations(context.Background(), "101"); len(regs) != 1 || regs[0].Transport != "TLS" {
		t.Fatalf("registration not recorded as TLS: %+v", regs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "102", "pw101")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	ds := wait(t, b.answered, "callee answered")

	keyForA := pbxKey(t, dc.InviteResponse.Body())
	keyForB := pbxKey(t, ds.InviteRequest.Body())
	// Each phone only ever sees the PBX's key for it, never the other phone's.
	if strings.Contains(string(ds.InviteRequest.Body()), keyB64(a.key)) ||
		strings.Contains(string(dc.InviteResponse.Body()), keyB64(b.key)) {
		t.Fatal("a phone's SRTP key leaked to the other phone")
	}
	portA := relayPort(t, dc.InviteResponse.Body())
	portB := relayPort(t, ds.InviteRequest.Body())

	a.sendSRTP(portA, "secret from 101")
	if got := b.recvSRTP(keyForB); got != "secret from 101" {
		t.Fatalf("102 got %q", got)
	}
	b.sendSRTP(portB, "secret from 102")
	if got := a.recvSRTP(keyForA); got != "secret from 102" {
		t.Fatalf("101 got %q", got)
	}

	if calls := srv.ActiveCalls(); len(calls) != 1 || calls[0].Encryption() != store.EncryptionFull {
		t.Fatalf("active call encryption wrong")
	}
	dc.Bye(ctx)
	wait(t, b.byes, "BYE at callee over TLS")
	if rec := lastCall(t, st); rec.Encryption != store.EncryptionFull {
		t.Errorf("call record encryption = %q, want full", rec.Encryption)
	}
}

func TestPlainPhoneCallsEncryptedPhone(t *testing.T) {
	srv, st, roots := startTLSPBX(t)
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer") // UDP, plain RTP
	b := newTLSPhone(t, srv, roots, "102", "answer")
	a.register("pw101")
	b.register("pw102")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "102", "pw101")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	ds := wait(t, b.answered, "callee answered")

	if info, _ := sdp.Parse(dc.InviteResponse.Body()); info.Secure || len(info.Cryptos) > 0 {
		t.Fatalf("plain caller got SRTP SDP:\n%s", dc.InviteResponse.Body())
	}
	keyForB := pbxKey(t, ds.InviteRequest.Body())
	portA := relayPort(t, dc.InviteResponse.Body())
	portB := relayPort(t, ds.InviteRequest.Body())

	a.sendRTP(portA, string(rtpBytes(t, "plain hello")))
	if got := b.recvSRTP(keyForB); got != "plain hello" {
		t.Fatalf("encrypted phone got %q", got)
	}
	b.sendSRTP(portB, "encrypted hello")
	if got := a.recvRTP(); got == "" || rtpPayload(t, []byte(got)) != "encrypted hello" {
		t.Fatalf("plain phone got %q", got)
	}

	dc.Bye(ctx)
	wait(t, b.byes, "BYE at callee")
	if rec := lastCall(t, st); rec.Encryption != store.EncryptionPartial {
		t.Errorf("call record encryption = %q, want partial", rec.Encryption)
	}
}

func TestRequireTLS(t *testing.T) {
	srv, st, roots := startTLSPBX(t)
	ctx := context.Background()
	ext, _ := st.GetExtension(ctx, "101")
	ext.RequireTLS = true
	if err := st.UpdateExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}

	// Plain registration is refused...
	plain := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	var uri sip.Uri
	sip.ParseUri("sip:101@"+srv.UDPAddr(), &uri)
	req := sip.NewRequest(sip.REGISTER, uri)
	req.AppendHeader(&plain.contact)
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := plain.client.Do(rctx, req, sipgo.ClientRequestRegisterBuild)
	if err == nil && res.StatusCode == 401 {
		res, err = plain.client.DoDigestAuth(rctx, req, res, sipgo.DigestAuth{Username: "101", Password: "pw101"})
	}
	if err != nil || res.StatusCode != 403 {
		t.Fatalf("plain REGISTER for TLS-only extension: %v %v, want 403", res, err)
	}

	// ...and so is a plain call from it, even with the right password.
	newCallPhone(t, srv.UDPAddr(), "102", "answer").register("pw102")
	_, err = plain.call(rctx, "102", "pw101")
	var de *sipgo.ErrDialogResponse
	if !errors.As(err, &de) || de.Res.StatusCode != 403 {
		t.Fatalf("plain call from TLS-only extension: %v, want 403", err)
	}

	// Over TLS with SRTP it works.
	secure := newTLSPhone(t, srv, roots, "101", "answer")
	secure.register("pw101")
	dc, err := secure.call(rctx, "102", "pw101")
	if err != nil {
		t.Fatalf("TLS call from TLS-only extension: %v", err)
	}
	dc.Bye(rctx)

	// TLS without SRTP is refused: "require encryption" covers the audio too.
	secure.key = nil
	_, err = secure.call(rctx, "102", "pw101")
	if !errors.As(err, &de) || de.Res.StatusCode != 488 {
		t.Fatalf("TLS call with plain audio from TLS-only extension: %v, want 488", err)
	}
}
