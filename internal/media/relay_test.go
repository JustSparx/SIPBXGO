package media

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func udp(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("cannot bind %s: %v", ip, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func port(c *net.UDPConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

func relayAddr(p int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p} }

func recv(t *testing.T, c *net.UDPConn) (string, bool) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 100)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func TestRelayForwardsAndLatches(t *testing.T) {
	pool := NewPortPool(30000, 30099)
	r, err := NewRelay(pool, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	phoneA, phoneB := udp(t, "127.0.0.1"), udp(t, "127.0.0.1")
	lo := netip.MustParseAddr("127.0.0.1")

	// A is "behind NAT": its SDP shows a private address with its real port.
	r.SetRemote(Caller, &sdp.Info{Addr: netip.MustParseAddr("192.168.1.5"), Port: port(phoneA), RTCPPort: port(phoneA) + 1}, lo)
	// B's SDP port is wrong (NAT rewrote it); latching must fix that.
	r.SetRemote(Callee, &sdp.Info{Addr: lo, Port: 9, RTCPPort: 10}, lo)
	r.Start()

	// B -> A works before A has sent anything (guess = signaling IP + SDP port).
	phoneB.WriteToUDP([]byte("hello A"), relayAddr(r.Legs[Callee].Port))
	if got, ok := recv(t, phoneA); !ok || got != "hello A" {
		t.Fatalf("A got %q ok=%v", got, ok)
	}
	// A -> B: A's real address is latched, B's too (from its previous send).
	phoneA.WriteToUDP([]byte("hello B"), relayAddr(r.Legs[Caller].Port))
	if got, ok := recv(t, phoneB); !ok || got != "hello B" {
		t.Fatalf("B got %q ok=%v", got, ok)
	}
	if r.Legs[Caller].PacketsIn.Load() != 1 || r.Legs[Callee].PacketsIn.Load() != 1 {
		t.Fatalf("counters: %s", r)
	}
}

func TestRelayDropsStrangers(t *testing.T) {
	pool := NewPortPool(30100, 30199)
	r, err := NewRelay(pool, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	phoneA, phoneB := udp(t, "127.0.0.1"), udp(t, "127.0.0.1")
	stranger := udp(t, "127.0.0.2")
	lo := netip.MustParseAddr("127.0.0.1")
	r.SetRemote(Caller, &sdp.Info{Addr: lo, Port: port(phoneA), RTCPPort: port(phoneA) + 1}, lo)
	r.SetRemote(Callee, &sdp.Info{Addr: lo, Port: port(phoneB), RTCPPort: port(phoneB) + 1}, lo)
	r.Start()

	stranger.WriteToUDP([]byte("injected"), relayAddr(r.Legs[Caller].Port))
	if got, ok := recv(t, phoneB); ok {
		t.Fatalf("stranger's packet was forwarded: %q", got)
	}
	if r.Legs[Caller].Dropped.Load() != 1 {
		t.Fatalf("dropped=%d, want 1", r.Legs[Caller].Dropped.Load())
	}
	// The stranger must not have hijacked where A's audio goes.
	phoneB.WriteToUDP([]byte("to A"), relayAddr(r.Legs[Callee].Port))
	if got, ok := recv(t, phoneA); !ok || got != "to A" {
		t.Fatalf("A got %q ok=%v", got, ok)
	}
}

func TestHoldSDPKeepsDestination(t *testing.T) {
	pool := NewPortPool(30200, 30299)
	r, err := NewRelay(pool, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	lo := netip.MustParseAddr("127.0.0.1")
	r.SetRemote(Caller, &sdp.Info{Addr: lo, Port: 4000, RTCPPort: 4001}, lo)
	r.SetRemote(Caller, &sdp.Info{Addr: netip.IPv4Unspecified(), Port: 4000, RTCPPort: 4001}, lo)
	if p := r.Legs[Caller].rtp.peer.Load(); p == nil || p.Addr() != lo {
		t.Fatalf("hold SDP clobbered destination: %v", p)
	}
}

func TestPortPoolRecycles(t *testing.T) {
	pool := NewPortPool(30301, 30308) // odd start rounds up: pairs 30302,30304,30306
	if pool.Available() != 3 {
		t.Fatalf("available=%d, want 3", pool.Available())
	}
	r, err := NewRelay(pool, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if pool.Available() != 1 {
		t.Fatalf("available=%d after relay, want 1", pool.Available())
	}
	if _, err := NewRelay(pool, quiet); err != ErrNoPorts {
		t.Fatalf("got %v, want ErrNoPorts", err)
	}
	if pool.Available() != 1 {
		t.Fatalf("failed relay leaked ports: available=%d", pool.Available())
	}
	r.Close()
	r.Close() // idempotent
	if pool.Available() != 3 {
		t.Fatalf("available=%d after close, want 3", pool.Available())
	}
}
