package security

import (
	"net/netip"
	"testing"
	"time"
)

func TestBanAfterThreshold(t *testing.T) {
	b := NewBanList(3, time.Minute, time.Hour, nil)
	now := time.Now()
	b.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")

	if b.Fail(ip) || b.Fail(ip) {
		t.Fatal("banned too early")
	}
	if !b.Fail(ip) {
		t.Fatal("not banned at threshold")
	}
	if !b.IsBanned(ip) {
		t.Fatal("IsBanned false after ban")
	}
	now = now.Add(time.Hour + time.Second)
	if b.IsBanned(ip) {
		t.Fatal("ban did not expire")
	}
}

func TestFailuresOutsideWindowDoNotCount(t *testing.T) {
	b := NewBanList(3, time.Minute, time.Hour, nil)
	now := time.Now()
	b.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")

	b.Fail(ip)
	b.Fail(ip)
	now = now.Add(2 * time.Minute)
	if b.Fail(ip) {
		t.Fatal("old failures should have aged out")
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	b := NewBanList(2, time.Minute, time.Hour, nil)
	ip := netip.MustParseAddr("203.0.113.9")
	b.Fail(ip)
	b.Succeed(ip)
	if b.Fail(ip) {
		t.Fatal("success should reset the count")
	}
}

func TestTrustedNeverBanned(t *testing.T) {
	b := NewBanList(1, time.Minute, time.Hour, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	ip := netip.MustParseAddr("10.1.2.3")
	if b.Fail(ip) || b.BanNow(ip) || b.IsBanned(ip) {
		t.Fatal("trusted address was banned")
	}
}

func TestMappedIPv4(t *testing.T) {
	b := NewBanList(1, time.Minute, time.Hour, nil)
	b.Fail(netip.MustParseAddr("::ffff:198.51.100.7"))
	if !b.IsBanned(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("IPv4-mapped address should ban the plain IPv4 address")
	}
}

func TestScannerAgent(t *testing.T) {
	if !IsScannerAgent("friendly-scanner") || !IsScannerAgent("SIPVicious 0.3") {
		t.Fatal("scanner not detected")
	}
	if IsScannerAgent("OBIHAI/OBi1032-5.1.11") {
		t.Fatal("real phone flagged as scanner")
	}
}
