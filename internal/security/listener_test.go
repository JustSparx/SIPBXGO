package security

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// guardedServer accepts on a guarded loopback listener; each connection is
// read until it closes, answering the first message when reply is set.
func guardedServer(t *testing.T, bans *BanList, reply bool) (addr string, closed <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gl := &Listener{Listener: ln, Bans: bans}
	t.Cleanup(func() { gl.Close() })
	done := make(chan struct{}, 16)
	go func() {
		for {
			c, err := gl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				answered := false
				for {
					if _, err := c.Read(buf); err != nil {
						done <- struct{}{}
						return
					}
					if reply && !answered {
						c.Write([]byte("SIP/2.0 401 Unauthorized\r\n\r\n"))
						answered = true
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), done
}

// visit connects, optionally sends a request (waiting for a reply if one is
// expected), then hangs up, and waits for the server to see the close.
func visit(t *testing.T, addr string, closed <-chan struct{}, send, awaitReply bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if send {
		c.Write([]byte("INVITE sip:00900442037699931@x SIP/2.0\r\n\r\n"))
		if awaitReply {
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(make([]byte, 512)); err != nil {
				t.Fatalf("no reply: %v", err)
			}
		}
	}
	c.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server never saw the connection close")
	}
}

var loopback = netip.MustParseAddr("127.0.0.1")

func TestHitAndRunGetsBanned(t *testing.T) {
	bans := NewBanList(3, time.Minute, time.Minute, nil)
	addr, closed := guardedServer(t, bans, false)

	for i := 0; i < 3; i++ {
		if bans.IsBanned(loopback) {
			t.Fatalf("banned after only %d hang-ups", i)
		}
		visit(t, addr, closed, true, false)
	}
	if !bans.IsBanned(loopback) {
		t.Fatal("not banned after 3 requests abandoned before a reply")
	}

	// Banned: the connection is closed on accept, before any data is read.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err == nil || isTimeout(err) {
		t.Fatalf("banned peer's connection stayed open: %v", err)
	}
}

func TestAnsweredOrSilentPeersAreNotPenalized(t *testing.T) {
	bans := NewBanList(1, time.Minute, time.Minute, nil)

	// A phone hangs up after its answer (e.g. its NAT mapping expired).
	addr, closed := guardedServer(t, bans, true)
	visit(t, addr, closed, true, true)
	// A port scan or health check connects and leaves without a word.
	addr, closed = guardedServer(t, bans, false)
	visit(t, addr, closed, false, false)

	if bans.IsBanned(loopback) {
		t.Fatal("banned a peer that did nothing wrong")
	}
}

func TestTrustedPeersAreNeverBannedForHangingUp(t *testing.T) {
	bans := NewBanList(1, time.Minute, time.Minute, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	addr, closed := guardedServer(t, bans, false)
	visit(t, addr, closed, true, false)
	if bans.IsBanned(loopback) {
		t.Fatal("banned a trusted address")
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
