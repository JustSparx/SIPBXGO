package media

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/audio"
	"github.com/pion/rtp"
)

// Loop is audio pre-encoded in both G.711 flavors, ready to be played to
// any phone as 20 ms RTP packets (hold music).
type Loop struct {
	ulaw, alaw []byte // length is a whole number of frames
}

// NewLoop encodes pcm (8 kHz mono) for playback, padding to whole frames.
func NewLoop(pcm []int16) *Loop {
	if rem := len(pcm) % audio.FrameSamples; rem != 0 {
		pcm = append(pcm, make([]int16, audio.FrameSamples-rem)...)
	}
	return &Loop{
		ulaw: audio.Encode(nil, pcm, audio.PCMU),
		alaw: audio.Encode(nil, pcm, audio.PCMA),
	}
}

// Duration of one pass through the loop.
func (l *Loop) Duration() time.Duration {
	return time.Duration(len(l.ulaw)) * time.Second / audio.SampleRate
}

// Player streams a Loop to an endpoint until stopped.
type Player struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
	Sent atomic.Uint64
}

// PlayTo starts streaming the loop to ep in ep's G.711 flavor.
func (l *Loop) PlayTo(ep *Endpoint) *Player {
	p := &Player{stop: make(chan struct{}), done: make(chan struct{})}
	go p.run(l, ep)
	return p
}

func (p *Player) run(l *Loop, ep *Endpoint) {
	defer close(p.done)
	pt := ep.PayloadType()
	data := l.ulaw
	if pt == audio.PCMA {
		data = l.alaw
	}
	var seed [10]byte
	rand.Read(seed[:])
	pkt := rtp.Packet{Header: rtp.Header{
		Version:        2,
		PayloadType:    uint8(pt),
		SequenceNumber: binary.BigEndian.Uint16(seed[0:]),
		Timestamp:      binary.BigEndian.Uint32(seed[2:]),
		SSRC:           binary.BigEndian.Uint32(seed[6:]),
		Marker:         true, // start of a new talk spurt
	}}
	buf := make([]byte, 0, 12+audio.FrameSamples)

	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for pos := 0; ; pos = (pos + audio.FrameSamples) % len(data) {
		select {
		case <-p.stop:
			return
		case <-t.C:
		}
		pkt.Payload = data[pos : pos+audio.FrameSamples]
		b, err := pkt.Header.MarshalTo(buf[:12])
		if err == nil {
			out := append(buf[:b], pkt.Payload...)
			if ep.Send(out, false) == nil {
				p.Sent.Add(1)
			}
		}
		pkt.Marker = false
		pkt.SequenceNumber++
		pkt.Timestamp += audio.FrameSamples
	}
}

// Stop ends playback and waits for the stream to finish. Safe to call twice.
func (p *Player) Stop() {
	p.once.Do(func() { close(p.stop) })
	<-p.done
}
