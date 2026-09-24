// Package security keeps SIP scanners and password guessers out.
//
// Any public SIP port gets probed within hours. The BanList counts auth
// failures per source IP and, past a threshold, silently ignores that IP for
// a while. Well-known scanner User-Agents are banned on first contact.
package security

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

type BanList struct {
	Threshold int
	Window    time.Duration
	Duration  time.Duration
	Trusted   []netip.Prefix

	mu       sync.Mutex
	failures map[netip.Addr][]time.Time
	banned   map[netip.Addr]time.Time // until
	now      func() time.Time
}

func NewBanList(threshold int, window, duration time.Duration, trusted []netip.Prefix) *BanList {
	return &BanList{
		Threshold: threshold,
		Window:    window,
		Duration:  duration,
		Trusted:   trusted,
		failures:  make(map[netip.Addr][]time.Time),
		banned:    make(map[netip.Addr]time.Time),
		now:       time.Now,
	}
}

// Ban describes an active ban, for display.
type Ban struct {
	Addr  netip.Addr
	Until time.Time
}

func (b *BanList) isTrusted(ip netip.Addr) bool {
	for _, p := range b.Trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBanned reports whether traffic from ip should be dropped.
func (b *BanList) IsBanned(ip netip.Addr) bool {
	ip = ip.Unmap()
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.banned[ip]
	if !ok {
		return false
	}
	if b.now().After(until) {
		delete(b.banned, ip)
		return false
	}
	return true
}

// Fail records an authentication failure and reports whether it caused a ban.
func (b *BanList) Fail(ip netip.Addr) (banned bool) {
	ip = ip.Unmap()
	if b.Threshold <= 0 || b.isTrusted(ip) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	cutoff := now.Add(-b.Window)
	kept := b.failures[ip][:0]
	for _, t := range b.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) >= b.Threshold {
		delete(b.failures, ip)
		b.banned[ip] = now.Add(b.Duration)
		return true
	}
	b.failures[ip] = kept
	return false
}

// Succeed clears the failure count after a successful authentication.
func (b *BanList) Succeed(ip netip.Addr) {
	ip = ip.Unmap()
	b.mu.Lock()
	delete(b.failures, ip)
	b.mu.Unlock()
}

// BanNow bans ip immediately (e.g. a scanner User-Agent) unless trusted.
func (b *BanList) BanNow(ip netip.Addr) bool {
	ip = ip.Unmap()
	if b.isTrusted(ip) {
		return false
	}
	b.mu.Lock()
	b.banned[ip] = b.now().Add(b.Duration)
	b.mu.Unlock()
	return true
}

// Unban lifts a ban and clears failures for ip.
func (b *BanList) Unban(ip netip.Addr) {
	ip = ip.Unmap()
	b.mu.Lock()
	delete(b.banned, ip)
	delete(b.failures, ip)
	b.mu.Unlock()
}

// Active returns current bans.
func (b *BanList) Active() []Ban {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	var out []Ban
	for ip, until := range b.banned {
		if now.Before(until) {
			out = append(out, Ban{Addr: ip, Until: until})
		}
	}
	return out
}

// Sweep drops expired bans and stale failure records. Call periodically.
func (b *BanList) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for ip, until := range b.banned {
		if now.After(until) {
			delete(b.banned, ip)
		}
	}
	cutoff := now.Add(-b.Window)
	for ip, ts := range b.failures {
		if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
			delete(b.failures, ip)
		}
	}
}

// scannerAgents are User-Agent substrings used by common SIP attack tools.
var scannerAgents = []string{
	"friendly-scanner", "sipvicious", "sipcli", "sip-scan",
	"iwar", "sundayddr", "vaxsipuseragent", "pplsip",
}

// IsScannerAgent reports whether a User-Agent belongs to a known SIP scanner.
func IsScannerAgent(ua string) bool {
	ua = strings.ToLower(ua)
	for _, s := range scannerAgents {
		if strings.Contains(ua, s) {
			return true
		}
	}
	return false
}
