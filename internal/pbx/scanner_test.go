package pbx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// The PBX must never open TCP connections: a dial-back to a peer that hung up
// holds up every other incoming request until it times out.
func TestNeverDialsOut(t *testing.T) {
	srv, _ := startPBX(t, 5)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			dialed <- struct{}{}
		}
	}()

	var uri sip.Uri
	if err := sip.ParseUri(fmt.Sprintf("sip:101@%s;transport=tcp", ln.Addr()), &uri); err != nil {
		t.Fatal(err)
	}
	req := sip.NewRequest(sip.OPTIONS, uri)
	req.SetTransport("TCP")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := srv.client.Do(ctx, req); err == nil {
		t.Fatal("request over a new TCP connection succeeded")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("refusing to dial took %v", d)
	}
	select {
	case <-dialed:
		t.Fatal("PBX opened a TCP connection")
	case <-time.After(100 * time.Millisecond):
	}
}

// A toll-fraud scanner sends an INVITE over TCP and hangs up at once. It gets
// banned, and then its connections are closed on sight.
func TestTCPHitAndRunScannerGetsBanned(t *testing.T) {
	srv, _ := startPBX(t, 3)
	addr := srv.tcp.Addr().String()
	banned := func() bool {
		for _, b := range srv.Bans() {
			if b.Addr == netip.MustParseAddr("127.0.0.1") {
				return true
			}
		}
		return false
	}

	// Whether the server answers before it notices the hang-up is a race, so
	// probe until the ban lands (each probe it can't answer counts).
	for i := 0; !banned(); i++ {
		if i == 50 {
			t.Fatal("scanner never banned")
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "INVITE sip:00900442037699931@127.0.0.1 SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKscan%d\r\n"+
			"From: <sip:1@127.0.0.1>;tag=s\r\nTo: <sip:00900442037699931@127.0.0.1>\r\n"+
			"Call-ID: scan%d\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", i, i)
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "OPTIONS sip:127.0.0.1 SIP/2.0\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 512)); err == nil {
		t.Fatalf("banned scanner got %d bytes back", n)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("banned scanner's connection was left open")
	}
}
