// Package media moves call audio: RTP/RTCP endpoints facing phones, the
// relay that joins two of them for a call, and the players and mixers that
// generate audio of their own.
//
// Phones behind NAT usually advertise private addresses in SDP and can't
// reach each other directly. Each phone gets its own RTP+RTCP socket pair on
// the server (an Endpoint); the relay forwards between the two endpoints of
// a call. Endpoints learn ("latch onto") each phone's real public address
// from the first packets it sends, which is what makes NAT work.
package media

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sdp"
)

// Relay connects leg 0 (caller) and leg 1 (callee).
type Relay struct {
	Legs [2]*Endpoint

	// blocked[i] stops forwarding to leg i (it is on hold, or hearing music).
	blocked [2]atomic.Bool

	mu      sync.Mutex
	players [2]*Player // hold music playing to each leg

	log       *slog.Logger
	closeOnce sync.Once
}

const (
	Caller = 0
	Callee = 1
)

// NewRelay allocates endpoints for both legs. Call Start to begin
// forwarding and Close when the call ends.
func NewRelay(pool *PortPool, log *slog.Logger) (*Relay, error) {
	r := &Relay{log: log}
	for i := range r.Legs {
		ep, err := NewEndpoint(pool, log)
		if err != nil {
			r.Close()
			return nil, err
		}
		r.Legs[i] = ep
	}
	return r, nil
}

// SetRemote tells a leg what its phone put in SDP and which IP it signals
// from. See Endpoint.SetRemote.
func (r *Relay) SetRemote(leg int, info *sdp.Info, signalIP netip.Addr) {
	r.Legs[leg].SetRemote(info, signalIP)
}

// SetCrypto sets a leg's SRTP keys. See Endpoint.SetCrypto.
func (r *Relay) SetCrypto(leg int, in, out *sdp.Crypto) error {
	return r.Legs[leg].SetCrypto(in, out)
}

// Start begins forwarding in both directions. Each packet is sent from the
// socket the receiving phone sends to (symmetric RTP keeps its NAT open);
// SRTP legs are decrypted on the way in and encrypted on the way out, so each
// phone only ever sees its own keys.
func (r *Relay) Start() {
	for i, ep := range r.Legs {
		to := 1 - i
		ep.Start(func(pkt []byte, rtcp bool) {
			if r.blocked[to].Load() {
				return
			}
			r.Legs[to].Send(pkt, rtcp)
		})
	}
}

// Hold puts the call on hold from side holder: nothing is forwarded in
// either direction, and the other side hears music if a loop is given.
func (r *Relay) Hold(holder int, music *Loop) {
	other := 1 - holder
	r.blocked[holder].Store(true)
	r.blocked[other].Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.players[other] == nil && music != nil {
		r.players[other] = music.PlayTo(r.Legs[other])
	}
}

// Resume ends a hold: music stops and audio flows both ways again.
func (r *Relay) Resume() {
	r.mu.Lock()
	for i, p := range r.players {
		if p != nil {
			p.Stop()
			r.players[i] = nil
		}
	}
	r.mu.Unlock()
	r.blocked[0].Store(false)
	r.blocked[1].Store(false)
}

// Idle is how long since either phone last sent media.
func (r *Relay) Idle() time.Duration {
	a, b := r.Legs[Caller].Idle(), r.Legs[Callee].Idle()
	if a < b {
		return a
	}
	return b
}

// Close stops forwarding and returns the ports to the pool. Safe to call
// more than once.
func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		r.Resume()
		for _, ep := range r.Legs {
			if ep != nil {
				ep.Close()
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
