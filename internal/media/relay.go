// Package media relays RTP/RTCP between the two phones in a call.
//
// Phones behind NAT usually advertise private addresses in SDP and can't
// reach each other directly. Each call leg gets its own RTP+RTCP socket pair
// on the server; each phone sends to its pair, and the relay forwards to the
// other phone. The relay learns ("latches onto") each phone's real public
// address from the first packets it sends, which is what makes NAT work.
package media

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

// PortPool hands out even/odd (RTP/RTCP) port pairs from a fixed range.
// Freed pairs go to the back of the queue so a port isn't reused right away,
// which keeps stray packets from a finished call out of the next one.
type PortPool struct {
	mu   sync.Mutex
	free []int // even RTP ports; RTCP is +1
}

func NewPortPool(min, max int) *PortPool {
	p := &PortPool{}
	if min%2 == 1 {
		min++
	}
	for port := min; port+1 <= max; port += 2 {
		p.free = append(p.free, port)
	}
	return p
}

// Available reports how many port pairs are free (2 per call).
func (p *PortPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.free)
}

var ErrNoPorts = errors.New("media: no free RTP ports")

// allocate binds an RTP/RTCP socket pair, skipping ports something else holds.
func (p *PortPool) allocate() (port int, rtp, rtcp *net.UDPConn, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for tries := len(p.free); tries > 0; tries-- {
		port, p.free = p.free[0], p.free[1:]
		rtp, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			p.free = append(p.free, port)
			continue
		}
		rtcp, err = net.ListenUDP("udp", &net.UDPAddr{Port: port + 1})
		if err != nil {
			rtp.Close()
			p.free = append(p.free, port)
			continue
		}
		return port, rtp, rtcp, nil
	}
	return 0, nil, nil, ErrNoPorts
}

func (p *PortPool) release(port int) {
	p.mu.Lock()
	p.free = append(p.free, port)
	p.mu.Unlock()
}

// path is one socket (RTP or RTCP) on a leg and where that phone is.
type path struct {
	rtcp    bool
	conn    *net.UDPConn
	peer    atomic.Pointer[netip.AddrPort] // where to send to the phone
	latched atomic.Bool                    // peer came from real traffic, not SDP
}

// Leg is the relay's side facing one phone.
type Leg struct {
	Port int // local RTP port the phone sends to (RTCP is Port+1)

	rtp, rtcp path
	// IPs allowed to send on this leg: the phone's signaling IP and SDP IP.
	allowed atomic.Pointer[[2]netip.Addr]
	mu      sync.Mutex
	sdpPort int

	// SRTP state; nil means plain RTP on this leg.
	crypto atomic.Pointer[legCrypto]

	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
	Dropped    atomic.Uint64 // from unexpected sources
	BadCrypto  atomic.Uint64 // failed SRTP authentication/decryption
}

// legCrypto holds one SRTP context per direction and packet type. Each
// context is only ever used by a single pump goroutine.
type legCrypto struct {
	in, out         *sdp.Crypto
	inRTP, inRTCP   *srtp.Context // decrypt what the phone sends
	outRTP, outRTCP *srtp.Context // encrypt what the phone receives
}

// Secure reports whether this leg uses SRTP.
func (l *Leg) Secure() bool { return l.crypto.Load() != nil }

func profile(suite string) (srtp.ProtectionProfile, error) {
	switch suite {
	case sdp.SuiteAES80:
		return srtp.ProtectionProfileAes128CmHmacSha1_80, nil
	case sdp.SuiteAES32:
		return srtp.ProtectionProfileAes128CmHmacSha1_32, nil
	}
	return 0, fmt.Errorf("media: unsupported SRTP suite %q", suite)
}

func newContext(c *sdp.Crypto, replay bool) (*srtp.Context, error) {
	prof, err := profile(c.Suite)
	if err != nil {
		return nil, err
	}
	var opts []srtp.ContextOption
	if replay {
		opts = append(opts, srtp.SRTPReplayProtection(64), srtp.SRTCPReplayProtection(64))
	}
	return srtp.CreateContext(c.Key[:16], c.Key[16:], prof, opts...)
}

// SetCrypto sets the SRTP keys for a leg: in is the phone's key (to decrypt
// what it sends), out is the PBX's key for that phone (to encrypt what it
// receives). Both nil makes the leg plain RTP. Unchanged keys keep their
// contexts (and rollover state), so a re-INVITE repeating the same keys is
// harmless.
func (r *Relay) SetCrypto(leg int, in, out *sdp.Crypto) error {
	l := r.Legs[leg]
	if in == nil || out == nil {
		if in != nil || out != nil {
			return errors.New("media: SRTP needs keys in both directions")
		}
		l.crypto.Store(nil)
		return nil
	}
	if cur := l.crypto.Load(); cur != nil && cur.in.Equal(in) && cur.out.Equal(out) {
		return nil
	}
	lc := &legCrypto{in: in, out: out}
	var err error
	if lc.inRTP, err = newContext(in, true); err != nil {
		return err
	}
	if lc.inRTCP, err = newContext(in, true); err != nil {
		return err
	}
	if lc.outRTP, err = newContext(out, false); err != nil {
		return err
	}
	if lc.outRTCP, err = newContext(out, false); err != nil {
		return err
	}
	l.crypto.Store(lc)
	return nil
}

// Relay connects leg 0 (caller) and leg 1 (callee).
type Relay struct {
	Legs [2]*Leg

	pool         *PortPool
	log          *slog.Logger
	lastActivity atomic.Int64 // unix nanos
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

const (
	Caller = 0
	Callee = 1
)

// NewRelay allocates sockets for both legs. Call Start to begin forwarding
// and Close when the call ends.
func NewRelay(pool *PortPool, log *slog.Logger) (*Relay, error) {
	r := &Relay{pool: pool, log: log}
	for i := range r.Legs {
		port, rtp, rtcp, err := pool.allocate()
		if err != nil {
			r.Close()
			return nil, err
		}
		l := &Leg{Port: port}
		l.rtp.conn, l.rtcp.conn = rtp, rtcp
		l.rtcp.rtcp = true
		r.Legs[i] = l
	}
	r.touch()
	return r, nil
}

// SetRemote tells a leg what its phone put in SDP and which IP it signals
// from. Until packets arrive, audio is sent to the best guess:
//   - the SDP address if it is the signaling address or publicly routable;
//   - otherwise (private SDP address behind NAT) the signaling IP with the
//     SDP port, which works for the many NATs that preserve ports.
//
// Once a phone has sent media its real address wins, unless a new SDP moves
// it to a different port. A hold SDP (c=0.0.0.0 or port 0) changes nothing.
func (r *Relay) SetRemote(leg int, info *sdp.Info, signalIP netip.Addr) {
	l := r.Legs[leg]
	signalIP = signalIP.Unmap()
	if info.Addr.IsUnspecified() || info.Port == 0 {
		return
	}
	l.allowed.Store(&[2]netip.Addr{signalIP, info.Addr})

	l.mu.Lock()
	defer l.mu.Unlock()
	if info.Port == l.sdpPort && l.rtp.latched.Load() {
		return
	}
	l.sdpPort = info.Port

	ip := info.Addr
	if ip != signalIP && signalIP.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		ip = signalIP
	}
	rtp := netip.AddrPortFrom(ip, uint16(info.Port))
	rtcp := netip.AddrPortFrom(ip, uint16(info.RTCPPort))
	l.rtp.peer.Store(&rtp)
	l.rtp.latched.Store(false)
	l.rtcp.peer.Store(&rtcp)
	l.rtcp.latched.Store(false)
}

// Start begins forwarding in both directions.
func (r *Relay) Start() {
	for i, l := range r.Legs {
		other := r.Legs[1-i]
		r.wg.Add(2)
		go r.pump(l, &l.rtp, other, &other.rtp)
		go r.pump(l, &l.rtcp, other, &other.rtcp)
	}
}

// pump reads from one phone and forwards to the other, sending from the
// socket that phone sends to (symmetric RTP keeps its NAT mapping open).
// SRTP legs are decrypted on the way in and encrypted on the way out, so
// each phone only ever sees its own keys.
func (r *Relay) pump(in *Leg, from *path, out *Leg, to *path) {
	defer r.wg.Done()
	buf := make([]byte, 2048)
	dec := make([]byte, 0, 2048)
	enc := make([]byte, 0, 2048+64)
	var hdr rtp.Header
	for {
		n, src, err := from.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // e.g. ICMP-triggered errors on some platforms
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		allowed := in.allowed.Load()
		if allowed == nil || (src.Addr() != allowed[0] && src.Addr() != allowed[1]) {
			in.Dropped.Add(1)
			continue
		}
		pkt := buf[:n]
		if lc := in.crypto.Load(); lc != nil {
			if from.rtcp {
				pkt, err = lc.inRTCP.DecryptRTCP(dec[:0], pkt, nil)
			} else {
				pkt, err = lc.inRTP.DecryptRTP(dec[:0], pkt, &hdr)
			}
			if err != nil {
				// Wrong key, replay, or a spoofed packet: never latch on it.
				in.BadCrypto.Add(1)
				continue
			}
		}
		if cur := from.peer.Load(); cur == nil || *cur != src || !from.latched.Load() {
			from.peer.Store(&src)
			from.latched.Store(true)
			r.log.Debug("media latched", "local_port", from.conn.LocalAddr().(*net.UDPAddr).Port, "peer", src)
		}
		in.PacketsIn.Add(1)
		r.touch()

		dst := to.peer.Load()
		if dst == nil {
			continue
		}
		if lc := out.crypto.Load(); lc != nil {
			if to.rtcp {
				pkt, err = lc.outRTCP.EncryptRTCP(enc[:0], pkt, nil)
			} else {
				pkt, err = lc.outRTP.EncryptRTP(enc[:0], pkt, &hdr)
			}
			if err != nil {
				continue
			}
		}
		if _, err := to.conn.WriteToUDPAddrPort(pkt, *dst); err == nil {
			out.PacketsOut.Add(1)
		}
	}
}

func (r *Relay) touch() { r.lastActivity.Store(time.Now().UnixNano()) }

// Idle is how long since either phone last sent media.
func (r *Relay) Idle() time.Duration {
	return time.Since(time.Unix(0, r.lastActivity.Load()))
}

// Close stops forwarding and returns the ports to the pool. Safe to call
// more than once.
func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		for _, l := range r.Legs {
			if l != nil {
				l.rtp.conn.Close()
				l.rtcp.conn.Close()
			}
		}
		r.wg.Wait()
		for _, l := range r.Legs {
			if l != nil {
				r.pool.release(l.Port)
			}
		}
	})
}

// String summarizes packet counts for logs.
func (r *Relay) String() string {
	a, b := r.Legs[Caller], r.Legs[Callee]
	return fmt.Sprintf("caller_sent=%d callee_sent=%d dropped=%d bad_srtp=%d",
		a.PacketsIn.Load(), b.PacketsIn.Load(), a.Dropped.Load()+b.Dropped.Load(),
		a.BadCrypto.Load()+b.BadCrypto.Load())
}
