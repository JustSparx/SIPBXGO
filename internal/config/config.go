// Package config loads SIPBXGO settings from environment variables.
//
// Every setting has a sensible default so `sipbxgo serve` works out of the
// box; in Docker the values come from the compose file's `environment:` block.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// DataDir holds the SQLite database (and later voicemail, MOH files).
	DataDir string

	// SIPAddr is the bind address for SIP over UDP and TCP, e.g. ":5060".
	SIPAddr string

	// PublicIP is the address phones use to reach this server. It is written
	// into Contact/Via headers and SDP so NATed phones send traffic back to
	// the right place. Empty means "use whatever address the socket has".
	PublicIP string

	// Realm is the digest authentication realm shown to phones.
	Realm string

	// Registration expiry bounds, in seconds. Phones asking for less than
	// MinExpires get 423 Interval Too Brief; more than MaxExpires is clamped.
	MinExpires int
	MaxExpires int

	// Auto-ban: an IP with BanThreshold failed auths inside BanWindow is
	// ignored for BanDuration. TrustedNets are never banned.
	BanThreshold int
	BanWindow    time.Duration
	BanDuration  time.Duration
	TrustedNets  []netip.Prefix

	// RTP relay port range (inclusive). Each call uses 4 ports.
	RTPPortMin int
	RTPPortMax int

	// RingTimeout is how long an unanswered call rings before giving up.
	RingTimeout time.Duration
	// MediaTimeout hangs up a call after this long with no RTP/RTCP from
	// either phone (e.g. a phone lost power mid-call).
	MediaTimeout time.Duration

	// HTTPAddr is where the web UI listens ("off" disables it). The default
	// is loopback-only; put it behind a TLS reverse proxy to reach it remotely.
	HTTPAddr string
	// SIPDomain is the server name shown in phone setup instructions (e.g.
	// pbx.example.com). Empty means show the public IP.
	SIPDomain string

	LogLevel string
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		DataDir:   env("SIPBX_DATA_DIR", "./data"),
		SIPAddr:   env("SIPBX_SIP_ADDR", ":5060"),
		PublicIP:  env("SIPBX_PUBLIC_IP", ""),
		Realm:     env("SIPBX_REALM", "sipbxgo"),
		LogLevel:  env("SIPBX_LOG_LEVEL", "info"),
		HTTPAddr:  env("SIPBX_HTTP_ADDR", "127.0.0.1:8080"),
		SIPDomain: env("SIPBX_SIP_DOMAIN", ""),
	}

	var err error
	if c.MinExpires, err = envInt("SIPBX_MIN_EXPIRES", 60); err != nil {
		return nil, err
	}
	if c.MaxExpires, err = envInt("SIPBX_MAX_EXPIRES", 300); err != nil {
		return nil, err
	}
	if c.MinExpires < 1 || c.MaxExpires < c.MinExpires {
		return nil, fmt.Errorf("invalid expiry bounds: min=%d max=%d", c.MinExpires, c.MaxExpires)
	}
	if c.BanThreshold, err = envInt("SIPBX_BAN_THRESHOLD", 5); err != nil {
		return nil, err
	}
	if c.BanWindow, err = envDuration("SIPBX_BAN_WINDOW", 10*time.Minute); err != nil {
		return nil, err
	}
	if c.BanDuration, err = envDuration("SIPBX_BAN_DURATION", time.Hour); err != nil {
		return nil, err
	}
	if c.TrustedNets, err = parseNets(env("SIPBX_TRUSTED_NETS", "")); err != nil {
		return nil, err
	}
	if c.PublicIP != "" {
		if _, err := netip.ParseAddr(c.PublicIP); err != nil {
			return nil, fmt.Errorf("SIPBX_PUBLIC_IP: %w", err)
		}
	}
	if c.RTPPortMin, c.RTPPortMax, err = parsePortRange(env("SIPBX_RTP_PORTS", "10000-10999")); err != nil {
		return nil, err
	}
	if c.RingTimeout, err = envDuration("SIPBX_RING_TIMEOUT", 60*time.Second); err != nil {
		return nil, err
	}
	if c.MediaTimeout, err = envDuration("SIPBX_MEDIA_TIMEOUT", 5*time.Minute); err != nil {
		return nil, err
	}
	return c, nil
}

// parsePortRange parses "10000-10999".
func parsePortRange(s string) (int, int, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("SIPBX_RTP_PORTS: want MIN-MAX, got %q", s)
	}
	min, err1 := strconv.Atoi(strings.TrimSpace(lo))
	max, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if err1 != nil || err2 != nil || min < 1024 || max > 65535 || max-min < 3 {
		return 0, 0, fmt.Errorf("SIPBX_RTP_PORTS: invalid range %q (need 1024-65535, at least 4 ports)", s)
	}
	return min, max, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// parseNets parses a comma-separated list of CIDRs or bare IPs.
func parseNets(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("SIPBX_TRUSTED_NETS: %w", err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("SIPBX_TRUSTED_NETS: %w", err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
