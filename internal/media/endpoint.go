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

// Endpoint is the server's media socket pair facing one phone. It learns
// where the phone really is (NAT latching), decrypts SRTP on the way in,
// hands packets to a handler, and encrypts on the way out.
//
// A call relay joins two endpoints back to back; the hold-music player and
// the conference mixer send into endpoints directly.
type Endpoint struct {
	Port int // local RTP port the phone sends to (RTCP is Port+1)

	rtp, rtcp path
	// IPs allowed to send on this endpoint: the phone's signaling and SDP IPs.
	allowed atomic.Pointer[[2]netip.Addr]
	mu      sync.Mutex
	sdpPort int

	// SRTP state; nil means plain RTP.
	crypto atomic.Pointer[legCrypto]

	sendMu sync.Mutex // serializes Send: the out SRTP contexts aren't goroutine-safe
	encBuf []byte

	lastActivity atomic.Int64 // unix nanos of the last packet from the phone

	// payloadType is the codec generated audio (hold music, conference mix)
	// is sent in: 0 (PCMU) or 8 (PCMA), whichever the phone negotiated.
	payloadType atomic.Int32

	pool      *PortPool
	log       *slog.Logger
	wg        sync.WaitGroup
	closeOnce sync.Once

	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
	Dropped    atomic.Uint64 // from unexpected sources
	BadCrypto  atomic.Uint64 // failed SRTP authentication/decryption
}

// Leg is the name the call relay uses for its endpoints.
type Leg = Endpoint

// path is one socket (RTP or RTCP) and where that phone is.
type path struct {
	rtcp    bool
	conn    *net.UDPConn
	peer    atomic.Pointer[netip.AddrPort] // where to send to the phone
	latched atomic.Bool                    // peer came from real traffic, not SDP
}

// Handler receives each authenticated, decrypted packet from the phone.
// pkt is only valid during the call.
type Handler func(pkt []byte, rtcp bool)

// NewEndpoint allocates a socket pair. Call Start to begin receiving and
// Close when done.
func NewEndpoint(pool *PortPool, log *slog.Logger) (*Endpoint, error) {
	port, rtpConn, rtcpConn, err := pool.allocate()
	if err != nil {
		return nil, err
	}
	e := &Endpoint{Port: port, pool: pool, log: log, encBuf: make([]byte, 0, 2048+64)}
	e.rtp.conn, e.rtcp.conn = rtpConn, rtcpConn
	e.rtcp.rtcp = true
	e.touch()
	return e, nil
}

// SetRemote tells the endpoint what its phone put in SDP and which IP it
// signals from. Until packets arrive, media is sent to the best guess:
//   - the SDP address if it is the signaling address or publicly routable;
//   - otherwise (private SDP address behind NAT) the signaling IP with the
//     SDP port, which works for the many NATs that preserve ports.
//
// Once the phone has sent media its real address wins, unless a new SDP
// moves it to a different port. A hold SDP (c=0.0.0.0 or port 0) changes
// nothing.
func (e *Endpoint) SetRemote(info *sdp.Info, signalIP netip.Addr) {
	signalIP = signalIP.Unmap()
	if info.Addr.IsUnspecified() || info.Port == 0 {
		return
	}
	e.allowed.Store(&[2]netip.Addr{signalIP, info.Addr})

	e.mu.Lock()
	defer e.mu.Unlock()
	if info.Port == e.sdpPort && e.rtp.latched.Load() {
		return
	}
	e.sdpPort = info.Port

	ip := info.Addr
	if ip != signalIP && signalIP.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		ip = signalIP
	}
	rtpAddr := netip.AddrPortFrom(ip, uint16(info.Port))
	rtcpAddr := netip.AddrPortFrom(ip, uint16(info.RTCPPort))
	e.rtp.peer.Store(&rtpAddr)
	e.rtp.latched.Store(false)
	e.rtcp.peer.Store(&rtcpAddr)
	e.rtcp.latched.Store(false)
}

// legCrypto holds one SRTP context per direction and packet type. Inbound
// contexts are used only by that path's reader goroutine; outbound ones only
// under sendMu.
type legCrypto struct {
	in, out         *sdp.Crypto
	inRTP, inRTCP   *srtp.Context // decrypt what the phone sends
	outRTP, outRTCP *srtp.Context // encrypt what the phone receives
}

// Secure reports whether this endpoint uses SRTP.
func (e *Endpoint) Secure() bool { return e.crypto.Load() != nil }

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

// SetCrypto sets the SRTP keys: in is the phone's key (to decrypt what it
// sends), out is the PBX's key for that phone (to encrypt what it receives).
// Both nil makes the endpoint plain RTP. Unchanged keys keep their contexts
// (and rollover state), so a re-INVITE repeating the same keys is harmless.
func (e *Endpoint) SetCrypto(in, out *sdp.Crypto) error {
	if in == nil || out == nil {
		if in != nil || out != nil {
			return errors.New("media: SRTP needs keys in both directions")
		}
		e.crypto.Store(nil)
		return nil
	}
	if cur := e.crypto.Load(); cur != nil && cur.in.Equal(in) && cur.out.Equal(out) {
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
	e.crypto.Store(lc)
	return nil
}

// Start begins reading from the phone; h receives each good packet.
func (e *Endpoint) Start(h Handler) {
	e.wg.Add(2)
	go e.read(&e.rtp, h)
	go e.read(&e.rtcp, h)
}

func (e *Endpoint) read(from *path, h Handler) {
	defer e.wg.Done()
	buf := make([]byte, 2048)
	dec := make([]byte, 0, 2048)
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
		allowed := e.allowed.Load()
		if allowed == nil || (src.Addr() != allowed[0] && src.Addr() != allowed[1]) {
			e.Dropped.Add(1)
			continue
		}
		pkt := buf[:n]
		if lc := e.crypto.Load(); lc != nil {
			if from.rtcp {
				pkt, err = lc.inRTCP.DecryptRTCP(dec[:0], pkt, nil)
			} else {
				pkt, err = lc.inRTP.DecryptRTP(dec[:0], pkt, &hdr)
			}
			if err != nil {
				// Wrong key, replay, or a spoofed packet: never latch on it.
				e.BadCrypto.Add(1)
				continue
			}
		}
		if cur := from.peer.Load(); cur == nil || *cur != src || !from.latched.Load() {
			from.peer.Store(&src)
			from.latched.Store(true)
			e.log.Debug("media latched", "local_port", from.conn.LocalAddr().(*net.UDPAddr).Port, "peer", src)
		}
		e.PacketsIn.Add(1)
		e.touch()
		if h != nil {
			h(pkt, from.rtcp)
		}
	}
}

// Send delivers a plain RTP or RTCP packet to the phone, encrypting it if
// the endpoint uses SRTP. It is sent from this endpoint's own socket, the
// one the phone sends to, so the phone's NAT lets it back in.
func (e *Endpoint) Send(pkt []byte, isRTCP bool) error {
	to := &e.rtp
	if isRTCP {
		to = &e.rtcp
	}
	dst := to.peer.Load()
	if dst == nil {
		return nil
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	out := pkt
	if lc := e.crypto.Load(); lc != nil {
		var err error
		if isRTCP {
			out, err = lc.outRTCP.EncryptRTCP(e.encBuf[:0], pkt, nil)
		} else {
			out, err = lc.outRTP.EncryptRTP(e.encBuf[:0], pkt, nil)
		}
		if err != nil {
			return err
		}
	}
	if _, err := to.conn.WriteToUDPAddrPort(out, *dst); err != nil {
		return err
	}
	e.PacketsOut.Add(1)
	return nil
}

// SetPayloadType sets the G.711 flavor for generated audio (0 or 8).
func (e *Endpoint) SetPayloadType(pt int) { e.payloadType.Store(int32(pt)) }

// PayloadType is the G.711 flavor for generated audio: 0 (PCMU) or 8 (PCMA).
func (e *Endpoint) PayloadType() int { return int(e.payloadType.Load()) }

func (e *Endpoint) touch() { e.lastActivity.Store(time.Now().UnixNano()) }

// Idle is how long since the phone last sent media.
func (e *Endpoint) Idle() time.Duration {
	return time.Since(time.Unix(0, e.lastActivity.Load()))
}

// Close stops reading and returns the ports to the pool. Safe to call more
// than once.
func (e *Endpoint) Close() {
	e.closeOnce.Do(func() {
		e.rtp.conn.Close()
		e.rtcp.conn.Close()
		e.wg.Wait()
		e.pool.release(e.Port)
	})
}
