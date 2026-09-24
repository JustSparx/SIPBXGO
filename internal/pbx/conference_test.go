package pbx

import (
	"context"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/audio"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
)

// talker streams a loud 440 Hz tone (PCMU) to port until stop is closed.
func (p *callPhone) talk(port int, stop <-chan struct{}) {
	pkt := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SSRC: 7}}
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	pcm := make([]int16, audio.FrameSamples)
	for n := 0; ; n++ {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		for i := range pcm {
			pcm[i] = int16(12000 * math.Sin(2*math.Pi*440*float64(n*audio.FrameSamples+i)/audio.SampleRate))
		}
		pkt.Payload = audio.Encode(nil, pcm, audio.PCMU)
		b, _ := pkt.Marshal()
		p.rtp.WriteToUDP(b, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		pkt.SequenceNumber++
		pkt.Timestamp += audio.FrameSamples
	}
}

// loudness receives audio for d and returns its RMS level.
func (p *callPhone) loudness(d time.Duration) float64 {
	deadline := time.Now().Add(d)
	buf := make([]byte, 2048)
	var sum float64
	var n int
	for time.Now().Before(deadline) {
		p.rtp.SetReadDeadline(deadline)
		k, _, err := p.rtp.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var pkt rtp.Packet
		if pkt.Unmarshal(buf[:k]) != nil {
			continue
		}
		for _, s := range audio.Decode(nil, pkt.Payload, int(pkt.PayloadType)) {
			sum += float64(s) * float64(s)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return math.Sqrt(sum / float64(n))
}

// sendDTMF sends an RFC 4733 key press as a phone does: a few packets
// sharing one timestamp, the last three marked as the end of the event.
func (p *callPhone) sendDTMF(port int, digit byte, ts uint32) {
	ev := map[byte]byte{'*': 10, '#': 11}[digit]
	if digit >= '0' && digit <= '9' {
		ev = digit - '0'
	}
	for i := 0; i < 5; i++ {
		end := byte(0)
		if i >= 2 {
			end = 0x80
		}
		pkt := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 101, SSRC: 7, SequenceNumber: uint16(ts/10) + uint16(i), Timestamp: ts, Marker: i == 0},
			Payload: []byte{ev, end | 10, 0, byte(160 * (i + 1))}}
		b, _ := pkt.Marshal()
		p.rtp.WriteToUDP(b, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	}
}

func members(srv *Server, room string) (admitted, waiting int) {
	for _, r := range srv.Engine().Conferences() {
		if r.Number == room {
			for _, m := range r.Members {
				if m.Admitted {
					admitted++
				} else {
					waiting++
				}
			}
		}
	}
	return
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConferenceMixing(t *testing.T) {
	srv, st := startPBX(t, 100)
	ctx := context.Background()
	st.CreateExtension(ctx, &store.Extension{Number: "103", Secret: "pw103", Enabled: true})
	if err := st.CreateRoom(ctx, &store.Room{Number: "800", Name: "Family"}); err != nil {
		t.Fatal(err)
	}
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	c := newCallPhone(t, srv.UDPAddr(), "103", "answer")

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dcA, err := a.call(cctx, "800", "pw101")
	if err != nil {
		t.Fatalf("join room: %v", err)
	}
	portA := relayPort(t, dcA.InviteResponse.Body())

	// Alone in the room: music.
	if lvl := a.loudness(400 * time.Millisecond); lvl < 300 {
		t.Fatalf("alone in the room but no music (rms %.0f)", lvl)
	}

	dcB, err := b.call(cctx, "800", "pw102")
	if err != nil {
		t.Fatal(err)
	}
	relayPort(t, dcB.InviteResponse.Body())
	eventually(t, "two members", func() bool { n, _ := members(srv, "800"); return n == 2 })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.talk(portA, stop) }()
	b.loudness(400 * time.Millisecond) // skip the join chime and music tail
	if lvl := b.loudness(500 * time.Millisecond); lvl < 3000 {
		t.Errorf("102 can't hear 101 (rms %.0f)", lvl)
	}
	a.loudness(100 * time.Millisecond)
	if lvl := a.loudness(500 * time.Millisecond); lvl > 500 {
		t.Errorf("101 hears itself (rms %.0f)", lvl)
	}

	// A third phone hears the speaker too.
	dcC, err := c.call(cctx, "800", "pw103")
	if err != nil {
		t.Fatal(err)
	}
	relayPort(t, dcC.InviteResponse.Body())
	c.loudness(400 * time.Millisecond)
	if lvl := c.loudness(500 * time.Millisecond); lvl < 3000 {
		t.Errorf("103 can't hear 101 (rms %.0f)", lvl)
	}
	close(stop)
	wg.Wait()

	// The speaker leaves; the others stay.
	dcA.Bye(cctx)
	eventually(t, "101 to leave", func() bool { n, _ := members(srv, "800"); return n == 2 })

	dcB.Bye(cctx)
	dcC.Bye(cctx)
	eventually(t, "room to close", func() bool { return len(srv.Engine().Conferences()) == 0 })
	eventually(t, "three call records", func() bool {
		calls, _ := st.ListCalls(ctx, "", 10, 0)
		return len(calls) == 3 && calls[0].Callee == "800" && calls[0].Status == store.CallAnswered
	})
}

func TestConferencePIN(t *testing.T) {
	srv, st := startPBX(t, 100)
	ctx := context.Background()
	st.CreateExtension(ctx, &store.Extension{Number: "103", Secret: "pw103", Enabled: true})
	st.CreateRoom(ctx, &store.Room{Number: "801", PIN: "4321"})
	a := newCallPhone(t, srv.UDPAddr(), "101", "answer")
	b := newCallPhone(t, srv.UDPAddr(), "102", "answer")
	c := newCallPhone(t, srv.UDPAddr(), "103", "answer")
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// A keys the PIN in-band (RFC 4733).
	dcA, err := a.call(cctx, "801", "pw101")
	if err != nil {
		t.Fatal(err)
	}
	portA := relayPort(t, dcA.InviteResponse.Body())
	eventually(t, "101 waiting for PIN", func() bool { _, w := members(srv, "801"); return w == 1 })
	for i, d := range []byte("4321") {
		a.sendDTMF(portA, d, uint32(1000*(i+1)))
	}
	eventually(t, "101 admitted", func() bool { n, _ := members(srv, "801"); return n == 1 })

	// B keys it by SIP INFO, ending with #.
	dcB, err := b.call(cctx, "801", "pw102")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range "4321#" {
		info := sip.NewRequest(sip.INFO, dcB.InviteResponse.Contact().Address)
		info.SetBody([]byte("Signal=" + string(d) + "\r\nDuration=160\r\n"))
		info.AppendHeader(sip.NewHeader("Content-Type", "application/dtmf-relay"))
		if res, err := dcB.Do(cctx, info); err != nil || res.StatusCode != 200 {
			t.Fatalf("INFO: %v %v", res, err)
		}
	}
	eventually(t, "102 admitted", func() bool { n, _ := members(srv, "801"); return n == 2 })

	// C gets it wrong three times and is hung up on.
	dcC, err := c.call(cctx, "801", "pw103")
	if err != nil {
		t.Fatal(err)
	}
	portC := relayPort(t, dcC.InviteResponse.Body())
	ts := uint32(5000)
	for try := 0; try < 3; try++ {
		for _, d := range []byte("0000") {
			c.sendDTMF(portC, d, ts)
			ts += 1000
		}
		time.Sleep(100 * time.Millisecond)
	}
	wait(t, c.byes, "BYE after three wrong PINs")
	if n, w := members(srv, "801"); n != 2 || w != 0 {
		t.Fatalf("after kick: %d admitted, %d waiting", n, w)
	}
	dcA.Bye(cctx)
	dcB.Bye(cctx)
}

func TestConferenceOverTLS(t *testing.T) {
	srv, st, roots := startTLSPBX(t)
	st.CreateRoom(context.Background(), &store.Room{Number: "800"})
	a := newTLSPhone(t, srv, roots, "101", "answer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dc, err := a.call(ctx, "800", "pw101")
	if err != nil {
		t.Fatal(err)
	}
	key := pbxKey(t, dc.InviteResponse.Body())
	// Music while alone arrives encrypted with the PBX's key for this phone.
	raw := a.recvRTP()
	if _, err := srtpCtx(t, key).DecryptRTP(nil, []byte(raw), nil); err != nil {
		t.Fatalf("conference audio to an SRTP phone isn't SRTP: %v", err)
	}
	if rs := srv.Engine().Conferences(); len(rs) != 1 || !rs[0].Members[0].Secure {
		t.Fatal("participant not reported as encrypted")
	}
	dc.Bye(ctx)
}
