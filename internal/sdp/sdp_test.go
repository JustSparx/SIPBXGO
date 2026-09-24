package sdp

import (
	"net/netip"
	"strings"
	"testing"
)

// Typical offer from a desk phone behind NAT (private address in SDP).
const phoneOffer = "v=0\r\n" +
	"o=- 12345 12345 IN IP4 192.168.1.182\r\n" +
	"s=-\r\n" +
	"c=IN IP4 192.168.1.182\r\n" +
	"t=0 0\r\n" +
	"m=audio 16600 RTP/AVP 9 0 8 101\r\n" +
	"a=rtpmap:9 G722/8000\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-15\r\n" +
	"a=ptime:20\r\n" +
	"a=sendrecv\r\n"

func TestParse(t *testing.T) {
	info, err := Parse([]byte(phoneOffer))
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != netip.MustParseAddr("192.168.1.182") || info.Port != 16600 || info.RTCPPort != 16601 {
		t.Fatalf("got %+v", info)
	}
	if info.Direction != "sendrecv" || info.OnHold() {
		t.Fatalf("direction %q hold=%v", info.Direction, info.OnHold())
	}
}

func TestParseMediaLevelOverrides(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\na=sendrecv\r\n" +
		"m=video 5000 RTP/AVP 96\r\nc=IN IP4 10.9.9.9\r\n" +
		"m=audio 4000 RTP/AVP 0\r\nc=IN IP4 10.0.0.2\r\na=rtcp:4005\r\na=sendonly\r\n"
	info, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != netip.MustParseAddr("10.0.0.2") || info.Port != 4000 || info.RTCPPort != 4005 {
		t.Fatalf("got %+v", info)
	}
	if info.Direction != "sendonly" || !info.OnHold() {
		t.Fatalf("direction %q", info.Direction)
	}
}

func TestParseOldStyleHold(t *testing.T) {
	body := strings.Replace(phoneOffer, "c=IN IP4 192.168.1.182", "c=IN IP4 0.0.0.0", 1)
	info, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !info.OnHold() {
		t.Fatal("c=0.0.0.0 should be hold")
	}
}

func TestParseNoAudio(t *testing.T) {
	if _, err := Parse([]byte("v=0\r\nc=IN IP4 1.2.3.4\r\nm=video 5000 RTP/AVP 96\r\n")); err != ErrNoAudio {
		t.Fatalf("got %v", err)
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("empty body accepted")
	}
}

func TestRewrite(t *testing.T) {
	relay := netip.MustParseAddr("203.0.113.10")
	out, err := Rewrite([]byte(phoneOffer), relay, 10002)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"o=- 12345 12345 IN IP4 203.0.113.10\r\n",
		"c=IN IP4 203.0.113.10\r\n",
		"m=audio 10002 RTP/AVP 9 0 8 101\r\n",
		"a=rtpmap:9 G722/8000\r\n", // codecs pass through untouched
		"a=fmtp:101 0-15\r\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "192.168.1.182") {
		t.Errorf("private address leaked:\n%s", s)
	}
	info, err := Parse(out)
	if err != nil || info.Addr != relay || info.Port != 10002 {
		t.Fatalf("reparse: %+v %v", info, err)
	}
}

func TestRewriteKeepsHoldAndDropsExtras(t *testing.T) {
	body := "v=0\r\no=- 1 2 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0\r\na=rtcp:4001 IN IP4 10.0.0.1\r\na=rtcp-mux\r\n" +
		"a=candidate:1 1 UDP 1 10.0.0.1 4000 typ host\r\na=ice-ufrag:x\r\n" +
		"m=video 5000 RTP/AVP 96\r\na=rtcp:5001\r\n"
	out, err := Rewrite([]byte(body), netip.MustParseAddr("203.0.113.10"), 10000)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "c=IN IP4 0.0.0.0\r\n") {
		t.Errorf("hold address not preserved:\n%s", s)
	}
	if !strings.Contains(s, "a=rtcp:10001 IN IP4 203.0.113.10\r\n") {
		t.Errorf("audio rtcp not rewritten:\n%s", s)
	}
	if !strings.Contains(s, "m=video 0 RTP/AVP 96\r\n") {
		t.Errorf("video not disabled:\n%s", s)
	}
	for _, gone := range []string{"a=candidate", "a=ice-ufrag", "a=rtcp-mux", "a=rtcp:5001"} {
		if strings.Contains(s, gone) {
			t.Errorf("%s should be dropped:\n%s", gone, s)
		}
	}
}

func TestRewriteToleratesBareLF(t *testing.T) {
	body := strings.ReplaceAll(phoneOffer, "\r\n", "\n")
	out, err := Rewrite([]byte(body), netip.MustParseAddr("203.0.113.10"), 10000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(out), "a=sendrecv\r\n") {
		t.Fatalf("output not CRLF-normalized:\n%q", out)
	}
}
