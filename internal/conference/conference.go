// Package conference mixes audio for conference rooms.
//
// Each participant's phone talks to the PBX through its own media endpoint
// (so NAT and SRTP work exactly as in normal calls). Every 20 ms a room's
// mixer takes one frame from each admitted participant and sends everyone
// the sum of all the others, never their own voice back.
//
// Rooms with a PIN hold newcomers in a waiting state: they hear a short
// prompt tone, key the PIN (then #), and only then join the mix. There are
// no voice prompts; tones are universal and need no recordings.
package conference

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/audio"
	"github.com/JustSparx/SIPBXGO/internal/media"
	"github.com/pion/rtp"
)

const (
	frame      = audio.FrameSamples
	maxBuffer  = 5 * frame // ~100 ms: older audio is dropped to keep latency low
	pinTimeout = 30 * time.Second
	maxTries   = 3
	rePrompt   = 3 * time.Second
)

type Config struct {
	Ports        *media.PortPool
	Music        []int16 // played to someone alone in a room; nil = silence
	MediaTimeout time.Duration
	Log          *slog.Logger
}

// Manager owns the active rooms.
type Manager struct {
	cfg   Config
	mu    sync.Mutex
	rooms map[string]*room
}

func New(cfg Config) *Manager {
	return &Manager{cfg: cfg, rooms: make(map[string]*room)}
}

// Participant is one phone in a room.
type Participant struct {
	ID     string
	Ext    string
	Name   string
	Room   string
	Joined time.Time

	ep     *media.Endpoint
	dtmfPT int
	pin    string
	// hangup ends the phone's call; it is called at most once, from its own
	// goroutine, for media timeouts and failed PINs.
	hangup func(reason string)

	mu           sync.Mutex
	room         *room
	fifo         []int16 // received audio waiting to be mixed
	admitted     bool
	entered      []byte
	tries        int
	waitingSince time.Time
	lastPrompt   time.Time
	tones        []int16 // queued for this participant only
	musicPos     int
	lastDTMF     uint32
	haveDTMF     bool
	kicked       bool
	left         bool

	// Outgoing RTP stream.
	hdr rtp.Header
	out []byte
}

// NewParticipant describes a phone about to join room. ep must already know
// the phone's address, codec and keys; dtmfPT is its telephone-event payload
// type (-1 if none); pin is the room PIN ("" for none).
func NewParticipant(ep *media.Endpoint, id, ext, name, room string, dtmfPT int, pin string, hangup func(string)) *Participant {
	var seed [10]byte
	rand.Read(seed[:])
	return &Participant{
		ID: id, Ext: ext, Name: name, Room: room, Joined: time.Now(),
		ep: ep, dtmfPT: dtmfPT, pin: pin, hangup: hangup,
		hdr: rtp.Header{
			Version:        2,
			SequenceNumber: binary.BigEndian.Uint16(seed[0:]),
			Timestamp:      binary.BigEndian.Uint32(seed[2:]),
			SSRC:           binary.BigEndian.Uint32(seed[6:]),
			Marker:         true,
		},
		out: make([]byte, 0, 12+frame),
	}
}

// Join adds p to its room (starting the room if needed) and starts
// receiving its audio.
func (m *Manager) Join(p *Participant) {
	m.mu.Lock()
	r := m.rooms[p.Room]
	if r == nil {
		r = &room{m: m, number: p.Room, stop: make(chan struct{})}
		m.rooms[p.Room] = r
		go r.run()
	}
	p.mu.Lock()
	p.room = r
	p.waitingSince = time.Now()
	if p.pin == "" {
		p.admitted = true
		p.tones = append(p.tones, audio.JoinTone...)
	}
	admitted := p.admitted
	p.mu.Unlock()
	r.add(p)
	m.mu.Unlock()

	if admitted {
		r.announce(p, audio.JoinTone)
	}
	m.cfg.Log.Info("conference join", "room", p.Room, "ext", p.Ext, "pin_required", p.pin != "")
	p.ep.Start(p.receive)
}

// Leave removes p from its room and releases its media. Safe to call twice.
func (m *Manager) Leave(p *Participant) {
	p.mu.Lock()
	if p.left {
		p.mu.Unlock()
		return
	}
	p.left = true
	r, admitted := p.room, p.admitted
	p.mu.Unlock()
	if r != nil {
		r.remove(p, admitted)
	}
	p.ep.Close()
	m.cfg.Log.Info("conference leave", "room", p.Room, "ext", p.Ext,
		"duration", time.Since(p.Joined).Round(time.Second))
}

// Digit delivers a keypad digit that arrived by SIP INFO rather than RTP.
func (p *Participant) Digit(d byte) { p.digit(d) }

// Secure reports whether the participant's audio is encrypted.
func (p *Participant) Secure() bool { return p.ep.Secure() }

// ---- status for the UI ----

type Member struct {
	Ext, Name string
	Joined    time.Time
	Admitted  bool
	Secure    bool
}

type RoomStatus struct {
	Number  string
	Members []Member
}

// Status lists active rooms and who is in them.
func (m *Manager) Status() []RoomStatus {
	m.mu.Lock()
	rooms := make([]*room, 0, len(m.rooms))
	for _, r := range m.rooms {
		rooms = append(rooms, r)
	}
	m.mu.Unlock()
	var out []RoomStatus
	for _, r := range rooms {
		rs := RoomStatus{Number: r.number}
		for _, p := range r.members() {
			p.mu.Lock()
			rs.Members = append(rs.Members, Member{Ext: p.Ext, Name: p.Name, Joined: p.Joined,
				Admitted: p.admitted, Secure: p.ep.Secure()})
			p.mu.Unlock()
		}
		out = append(out, rs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

// ---- receiving ----

func (p *Participant) receive(pkt []byte, isRTCP bool) {
	if isRTCP {
		return
	}
	var h rtp.Header
	n, err := h.Unmarshal(pkt)
	if err != nil || n > len(pkt) {
		return
	}
	payload := pkt[n:]
	if h.Padding && len(payload) > 0 {
		pad := int(payload[len(payload)-1])
		if pad > len(payload) {
			return
		}
		payload = payload[:len(payload)-pad]
	}
	pt := int(h.PayloadType)
	switch {
	case pt == p.dtmfPT && p.dtmfPT >= 0:
		p.dtmfEvent(h.Timestamp, payload)
	case pt == audio.PCMU || pt == audio.PCMA:
		p.mu.Lock()
		p.fifo = audio.Decode(p.fifo, payload, pt)
		if len(p.fifo) > maxBuffer {
			p.fifo = append(p.fifo[:0], p.fifo[len(p.fifo)-maxBuffer:]...)
		}
		p.mu.Unlock()
	}
	// Anything else (comfort noise, unknown codecs) is ignored.
}

// dtmfEvent handles an RFC 4733 telephone-event packet. A key press is a
// run of packets sharing one timestamp, ending with (usually three) packets
// with the end bit; the first end packet counts the digit.
func (p *Participant) dtmfEvent(ts uint32, payload []byte) {
	if len(payload) < 4 || payload[1]&0x80 == 0 {
		return
	}
	p.mu.Lock()
	dup := p.haveDTMF && p.lastDTMF == ts
	p.lastDTMF, p.haveDTMF = ts, true
	p.mu.Unlock()
	if dup {
		return
	}
	const keys = "0123456789*#"
	if ev := int(payload[0]); ev < len(keys) {
		p.digit(keys[ev])
	}
}

func (p *Participant) digit(d byte) {
	p.mu.Lock()
	if p.admitted || p.kicked {
		p.mu.Unlock()
		return
	}
	if d != '#' {
		p.entered = append(p.entered, d)
		if len(p.entered) < len(p.pin) {
			p.mu.Unlock()
			return
		}
	}
	ok := string(p.entered) == p.pin
	p.entered = p.entered[:0]
	var kick bool
	if ok {
		p.admitted = true
		p.tones = append(p.tones[:0], audio.JoinTone...)
	} else {
		p.tries++
		p.tones = append(p.tones[:0], audio.ErrorTone...)
		p.lastPrompt = time.Now() // prompt again after the error tone
		kick = p.tries >= maxTries
	}
	r := p.room
	p.mu.Unlock()

	switch {
	case ok:
		r.m.cfg.Log.Info("conference PIN accepted", "room", p.Room, "ext", p.Ext)
		r.announce(p, audio.JoinTone)
	case kick:
		r.m.cfg.Log.Warn("conference PIN failed, hanging up", "room", p.Room, "ext", p.Ext)
		// Let the error tone play before hanging up.
		time.AfterFunc(audio.Duration(len(audio.ErrorTone))+200*time.Millisecond, func() { p.kick("wrong PIN") })
	}
}

func (p *Participant) kick(reason string) {
	p.mu.Lock()
	if p.kicked || p.left {
		p.mu.Unlock()
		return
	}
	p.kicked = true
	p.mu.Unlock()
	go p.hangup(reason)
}

// ---- room and mixer ----

type room struct {
	m      *Manager
	number string
	mu     sync.Mutex
	parts  []*Participant
	stop   chan struct{}
}

func (r *room) add(p *Participant) {
	r.mu.Lock()
	r.parts = append(r.parts, p)
	r.mu.Unlock()
}

func (r *room) members() []*Participant {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Participant(nil), r.parts...)
}

func (r *room) remove(p *Participant, wasAdmitted bool) {
	r.mu.Lock()
	for i, q := range r.parts {
		if q == p {
			r.parts = append(r.parts[:i], r.parts[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	if wasAdmitted {
		r.announce(p, audio.LeaveTone)
	}
	// Close the room once empty. Holding the manager lock while checking
	// means a concurrent Join either sees the room gone or keeps it open.
	r.m.mu.Lock()
	r.mu.Lock()
	empty := len(r.parts) == 0
	r.mu.Unlock()
	if empty && r.m.rooms[r.number] == r {
		delete(r.m.rooms, r.number)
		close(r.stop)
	}
	r.m.mu.Unlock()
}

// announce queues a tone for every admitted participant except p.
func (r *room) announce(p *Participant, tone []int16) {
	for _, q := range r.members() {
		if q == p {
			continue
		}
		q.mu.Lock()
		if q.admitted {
			q.tones = append(q.tones, tone...)
		}
		q.mu.Unlock()
	}
}

func (r *room) run() {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.tick()
		}
	}
}

// tick produces one 20 ms frame for everyone in the room.
func (r *room) tick() {
	parts := r.members()
	frames := make([][]int16, len(parts))
	var sum [frame]int32
	admitted := 0
	for i, p := range parts {
		p.mu.Lock()
		if p.admitted {
			admitted++
			if len(p.fifo) >= frame {
				f := make([]int16, frame)
				copy(f, p.fifo[:frame])
				p.fifo = append(p.fifo[:0], p.fifo[frame:]...)
				frames[i] = f
				for j, s := range f {
					sum[j] += int32(s)
				}
			}
		} else {
			p.fifo = p.fifo[:0] // waiting for PIN: not heard by the room
		}
		p.mu.Unlock()
	}

	music := r.m.cfg.Music
	now := time.Now()
	for i, p := range parts {
		var out [frame]int16
		p.mu.Lock()
		switch {
		case !p.admitted:
			if now.Sub(p.waitingSince) > pinTimeout {
				p.mu.Unlock()
				p.kick("no PIN entered")
				continue
			}
			if len(p.tones) == 0 && now.Sub(p.lastPrompt) >= rePrompt {
				p.tones = append(p.tones, audio.PromptTone...)
				p.lastPrompt = now
			}
		case admitted == 1 && len(music) > 0:
			// Alone in the room: music until someone else arrives.
			for j := range out {
				out[j] = music[p.musicPos] / 2
				p.musicPos = (p.musicPos + 1) % len(music)
			}
		default:
			for j := range out {
				v := sum[j]
				if frames[i] != nil {
					v -= int32(frames[i][j]) // never hear yourself
				}
				out[j] = audio.Clip(v)
			}
		}
		if n := len(p.tones); n > 0 {
			k := min(n, frame)
			audio.MixInto(out[:k], p.tones[:k])
			p.tones = p.tones[k:]
		}
		p.mu.Unlock()

		if r.m.cfg.MediaTimeout > 0 && p.ep.Idle() > r.m.cfg.MediaTimeout {
			p.kick("no audio")
			continue
		}
		p.send(out[:])
	}
}

// send encodes one frame in the participant's codec and sends it.
func (p *Participant) send(pcm []int16) {
	pt := p.ep.PayloadType()
	p.hdr.PayloadType = uint8(pt)
	n, err := p.hdr.MarshalTo(p.out[:cap(p.out)])
	if err != nil {
		return
	}
	pkt := audio.Encode(p.out[:n], pcm, pt)
	p.ep.Send(pkt, false)
	p.hdr.Marker = false
	p.hdr.SequenceNumber++
	p.hdr.Timestamp += frame
}
