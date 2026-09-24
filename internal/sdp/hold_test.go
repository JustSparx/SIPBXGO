package sdp

import (
	"strings"
	"testing"
)

func TestSetDirectionAndVersion(t *testing.T) {
	body := []byte(strings.Replace(phoneOffer, "a=sendrecv\r\n", "", 1) + "m=video 0 RTP/AVP 96\r\n")
	out := string(BumpVersion(SetDirection([]byte(phoneOffer), "recvonly")))
	if !strings.Contains(out, "a=recvonly\r\n") || strings.Contains(out, "a=sendrecv") {
		t.Errorf("direction not replaced:\n%s", out)
	}
	if !strings.Contains(out, "o=- 12345 12346 IN IP4") {
		t.Errorf("version not bumped:\n%s", out)
	}
	// Direction goes into the audio section even when a later stream follows.
	out = string(SetDirection(body, "inactive"))
	if i, j := strings.Index(out, "a=inactive"), strings.Index(out, "m=video"); i < 0 || i > j {
		t.Errorf("direction not placed in the audio section:\n%s", out)
	}
	if info, _ := Parse([]byte(out)); info.Direction != "inactive" || !info.OnHold() {
		t.Errorf("parsed direction %q", info.Direction)
	}
}

func TestAnswerDirectionAndG711(t *testing.T) {
	for offer, want := range map[string]string{"sendonly": "recvonly", "recvonly": "sendonly", "inactive": "inactive", "sendrecv": "sendrecv"} {
		if got := AnswerDirection(offer); got != want {
			t.Errorf("%s -> %s, want %s", offer, got, want)
		}
	}
	info, _ := Parse([]byte(phoneOffer)) // m=audio ... 9 0 8 101
	if info.G711() != 0 || len(info.Formats) != 4 {
		t.Errorf("formats %v g711 %d", info.Formats, info.G711())
	}
	info.Formats = []int{9, 8, 0}
	if info.G711() != 8 {
		t.Error("A-law preference ignored")
	}
}
