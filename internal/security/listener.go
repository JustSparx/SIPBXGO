package security

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
)

// Listener guards a SIP TCP or TLS listener. Connections from banned IPs are
// closed as soon as they are accepted, and a peer that sends a request and
// hangs up before getting any reply counts as a failure toward a ban: phones
// wait for their answers, toll-fraud scanners fire an INVITE and disconnect.
type Listener struct {
	net.Listener
	Bans *BanList
	Log  *slog.Logger
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := addrIP(c.RemoteAddr())
		if l.Bans.IsBanned(ip) {
			c.Close()
			continue
		}
		return &guardedConn{Conn: c, l: l, ip: ip}, nil
	}
}

func addrIP(a net.Addr) netip.Addr {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

type guardedConn struct {
	net.Conn
	l          *Listener
	ip         netip.Addr
	got, sent  atomic.Bool
	reportOnce sync.Once
}

func (c *guardedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.got.Store(true)
	}
	// Our own close (net.ErrClosed) and read deadlines are not the peer's doing.
	if err != nil && c.got.Load() && !c.sent.Load() &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
		c.reportOnce.Do(c.hungUp)
	}
	return n, err
}

func (c *guardedConn) Write(b []byte) (int, error) {
	c.sent.Store(true)
	return c.Conn.Write(b)
}

func (c *guardedConn) hungUp() {
	if c.l.Bans.Fail(c.ip) && c.l.Log != nil {
		c.l.Log.Warn("banned ip that keeps hanging up before a reply",
			"ip", c.ip, "duration", c.l.Bans.Duration)
	}
}
