package sdp

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// Offer from a phone doing SDES-SRTP (as Linphone and most desk phones do).
const srtpOffer = "v=0\r\n" +
	"o=- 5 5 IN IP4 10.0.0.9\r\n" +
	"s=-\r\n" +
	"c=IN IP4 10.0.0.9\r\n" +
	"t=0 0\r\n" +
	"m=audio 7078 RTP/SAVP 0 101\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^31\r\n" +
	"a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj\r\n" +
	"a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:bm90IGEgdmFsaWQga2V5IGJ1dCB1bnN1cHBvcnRlZCBzdWl0ZSBhbnl3YXk=\r\n" +
	"a=zrtp-hash:1.10 abcdef\r\n"

func TestParseCryptos(t *testing.T) {
	info, err := Parse([]byte(srtpOffer))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Secure {
		t.Fatal("RTP/SAVP not detected as secure")
	}
	// The AES-256 line is skipped as unsupported.
	if len(info.Cryptos) != 2 || info.Cryptos[0].Tag != 1 || info.Cryptos[0].Suite != SuiteAES80 ||
		info.Cryptos[1].Suite != SuiteAES32 || len(info.Cryptos[0].Key) != KeyLen {
		t.Fatalf("cryptos: %+v", info.Cryptos)
	}
}

func TestParseCryptoRejectsMKIAndBadKeys(t *testing.T) {
	for _, v := range []string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4", // MKI
		"1 AES_CM_128_HMAC_SHA1_80 inline:c2hvcnQ=",                                          // wrong length
		"x AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",          // bad tag
	} {
		if c, _ := parseCrypto(v); c != nil {
			t.Errorf("accepted %q", v)
		}
	}
	// Missing base64 padding is tolerated.
	if c, err := parseCrypto("1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"); err != nil || c == nil {
		t.Errorf("good line rejected: %v", err)
	}
}

func TestRewriteToSRTP(t *testing.T) {
	ours, err := NewCrypto(1, SuiteAES80)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Rewrite([]byte(phoneOffer), netip.MustParseAddr("203.0.113.10"), 10000, ours)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Secure || len(info.Cryptos) != 1 || !info.Cryptos[0].Equal(ours) {
		t.Fatalf("rewritten SDP not keyed with our crypto:\n%s", out)
	}
	if !strings.Contains(string(out), "m=audio 10000 RTP/SAVP 9 0 8 101\r\n") {
		t.Errorf("profile not switched to SAVP:\n%s", out)
	}
	// a=crypto belongs in the media section, after c= and the m= line.
	if bytes.Index(out, []byte("a=crypto")) < bytes.Index(out, []byte("m=audio")) {
		t.Errorf("a=crypto placed before the media line:\n%s", out)
	}
}

func TestRewriteSRTPToPlainDropsKeys(t *testing.T) {
	out, err := Rewrite([]byte(srtpOffer), netip.MustParseAddr("203.0.113.10"), 10000, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "m=audio 10000 RTP/AVP 0 101\r\n") {
		t.Errorf("profile not switched to AVP:\n%s", s)
	}
	for _, gone := range []string{"a=crypto", "zrtp-hash", "WVNfX19z"} {
		if strings.Contains(s, gone) {
			t.Errorf("%s leaked into plain SDP:\n%s", gone, s)
		}
	}
}

func TestRewriteReplacesPhoneKeys(t *testing.T) {
	ours, _ := NewCrypto(1, SuiteAES80)
	out, err := Rewrite([]byte(srtpOffer), netip.MustParseAddr("203.0.113.10"), 10000, ours)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "a=crypto"); n != 1 {
		t.Fatalf("want exactly our crypto line, got %d:\n%s", n, out)
	}
	if strings.Contains(string(out), "WVNfX19z") {
		t.Fatal("phone's key leaked to the other side")
	}
}

func TestAudioProto(t *testing.T) {
	cases := map[[2]string]string{
		{"RTP/AVP", "s"}: "RTP/SAVP", {"RTP/AVPF", "s"}: "RTP/SAVPF", {"RTP/SAVP", "p"}: "RTP/AVP",
		{"RTP/SAVPF", "p"}: "RTP/AVPF", {"UDP/TLS/RTP/SAVPF", "s"}: "RTP/SAVPF",
	}
	for in, want := range cases {
		if got := audioProto(in[0], in[1] == "s"); got != want {
			t.Errorf("audioProto(%s, %s) = %s, want %s", in[0], in[1], got, want)
		}
	}
}
