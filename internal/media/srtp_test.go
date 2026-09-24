package media

import (
	"net"
	"net/netip"
	"testing"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

func rtpPacket(t *testing.T, seq uint16, payload string) []byte {
	t.Helper()
	p := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: seq, Timestamp: uint32(seq) * 160, SSRC: 0xabc}, Payload: []byte(payload)}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func payloadOf(t *testing.T, b []byte) string {
	t.Helper()
	var p rtp.Packet
	if err := p.Unmarshal(b); err != nil {
		t.Fatalf("not RTP: %v", err)
	}
	return string(p.Payload)
}

func ctx(t *testing.T, c *sdp.Crypto) *srtp.Context {
	t.Helper()
	x, err := srtp.CreateContext(c.Key[:16], c.Key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func recvRaw(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	got, ok := recv(t, c)
	if !ok {
		return nil
	}
	return []byte(got)
}

// setupSecure builds a relay with plain phone A and SRTP phone B.
func setupMixed(t *testing.T) (r *Relay, a, b *net.UDPConn, phoneKey, pbxKey *sdp.Crypto) {
	t.Helper()
	r, err := NewRelay(NewPortPool(30400, 30499), quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	a, b = udp(t, "127.0.0.1"), udp(t, "127.0.0.1")
	lo := netip.MustParseAddr("127.0.0.1")
	r.SetRemote(Caller, &sdp.Info{Addr: lo, Port: port(a), RTCPPort: port(a) + 1}, lo)
	r.SetRemote(Callee, &sdp.Info{Addr: lo, Port: port(b), RTCPPort: port(b) + 1}, lo)
	phoneKey, _ = sdp.NewCrypto(1, sdp.SuiteAES80)
	pbxKey, _ = sdp.NewCrypto(1, sdp.SuiteAES80)
	if err := r.SetCrypto(Callee, phoneKey, pbxKey); err != nil {
		t.Fatal(err)
	}
	r.Start()
	return
}

func TestSRTPToPlain(t *testing.T) {
	r, a, b, phoneKey, pbxKey := setupMixed(t)
	if r.Legs[Caller].Secure() || !r.Legs[Callee].Secure() {
		t.Fatal("wrong Secure() flags")
	}

	// B encrypts with its own key; A must receive plain RTP.
	enc, err := ctx(t, phoneKey).EncryptRTP(nil, rtpPacket(t, 1, "from B"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b.WriteToUDP(enc, relayAddr(r.Legs[Callee].Port))
	if got := recvRaw(t, a); got == nil || payloadOf(t, got) != "from B" {
		t.Fatalf("A got %q", got)
	}

	// A sends plain; B must receive SRTP keyed with the PBX's key for B.
	a.WriteToUDP(rtpPacket(t, 1, "from A"), relayAddr(r.Legs[Caller].Port))
	got := recvRaw(t, b)
	if got == nil {
		t.Fatal("B got nothing")
	}
	if string(got) == string(rtpPacket(t, 1, "from A")) {
		t.Fatal("B received plaintext")
	}
	dec, err := ctx(t, pbxKey).DecryptRTP(nil, got, nil)
	if err != nil || payloadOf(t, dec) != "from A" {
		t.Fatalf("B could not decrypt with the PBX key: %v", err)
	}
}

func TestSRTPRejectsUnauthenticated(t *testing.T) {
	r, a, b, _, _ := setupMixed(t)
	// Plain (or wrongly keyed) packets on an SRTP leg are dropped, not latched.
	wrong, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	enc, _ := ctx(t, wrong).EncryptRTP(nil, rtpPacket(t, 1, "forged"), nil)
	b.WriteToUDP(rtpPacket(t, 1, "plain"), relayAddr(r.Legs[Callee].Port))
	b.WriteToUDP(enc, relayAddr(r.Legs[Callee].Port))
	if got := recvRaw(t, a); got != nil {
		t.Fatalf("unauthenticated packet forwarded: %q", got)
	}
	if n := r.Legs[Callee].BadCrypto.Load(); n != 2 {
		t.Fatalf("BadCrypto = %d, want 2", n)
	}
	if r.Legs[Callee].rtp.latched.Load() {
		t.Fatal("latched onto an unauthenticated packet")
	}
}

func TestSRTPBothSides(t *testing.T) {
	r, err := NewRelay(NewPortPool(30500, 30599), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a, b := udp(t, "127.0.0.1"), udp(t, "127.0.0.1")
	lo := netip.MustParseAddr("127.0.0.1")
	r.SetRemote(Caller, &sdp.Info{Addr: lo, Port: port(a), RTCPPort: port(a) + 1}, lo)
	r.SetRemote(Callee, &sdp.Info{Addr: lo, Port: port(b), RTCPPort: port(b) + 1}, lo)
	aKey, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	bKey, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	pbxA, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	pbxB, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	r.SetCrypto(Caller, aKey, pbxA)
	r.SetCrypto(Callee, bKey, pbxB)
	r.Start()

	enc, _ := ctx(t, aKey).EncryptRTP(nil, rtpPacket(t, 7, "secret"), nil)
	a.WriteToUDP(enc, relayAddr(r.Legs[Caller].Port))
	got := recvRaw(t, b)
	// B only knows the PBX's key for B; A's key never reaches it.
	dec, err := ctx(t, pbxB).DecryptRTP(nil, got, nil)
	if err != nil || payloadOf(t, dec) != "secret" {
		t.Fatalf("B decrypt: %v", err)
	}
}

func TestSetCryptoKeepsContextForSameKeys(t *testing.T) {
	r, err := NewRelay(NewPortPool(30600, 30699), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	in, _ := sdp.NewCrypto(1, sdp.SuiteAES80)
	out, _ := sdp.NewCrypto(1, sdp.SuiteAES32)
	r.SetCrypto(Caller, in, out)
	first := r.Legs[Caller].crypto.Load()
	same := *in
	r.SetCrypto(Caller, &same, out)
	if r.Legs[Caller].crypto.Load() != first {
		t.Fatal("identical keys rebuilt the SRTP contexts")
	}
	if err := r.SetCrypto(Caller, in, nil); err == nil {
		t.Fatal("half-keyed leg accepted")
	}
	r.SetCrypto(Caller, nil, nil)
	if r.Legs[Caller].Secure() {
		t.Fatal("leg still secure after clearing keys")
	}
}
