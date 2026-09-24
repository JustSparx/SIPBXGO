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

	LogLevel string
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		DataDir:  env("SIPBX_DATA_DIR", "./data"),
		SIPAddr:  env("SIPBX_SIP_ADDR", ":5060"),
		PublicIP: env("SIPBX_PUBLIC_IP", ""),
		Realm:    env("SIPBX_REALM", "sipbxgo"),
		LogLevel: env("SIPBX_LOG_LEVEL", "info"),
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
	return c, nil
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
