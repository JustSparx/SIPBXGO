package b2bua

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/conference"
	"github.com/JustSparx/SIPBXGO/internal/media"
	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/JustSparx/SIPBXGO/internal/sipauth"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// confLeg is one phone's call into a conference room. Unlike a normal call
// there is no second phone: the PBX answers and the room's mixer is the far
// end.
type confLeg struct {
	id      string
	caller  *store.Extension
	room    *store.Room
	ds      *sipgo.DialogServerSession
	ep      *media.Endpoint
	p       *conference.Participant
	log     *slog.Logger
	started time.Time

	mu      sync.Mutex
	ours    *sdp.Crypto // PBX's SRTP key for the phone (nil = plain)
	local   sdp.Local   // last SDP the PBX sent
	endOnce sync.Once
}

// joinConference answers a call to a room number and puts the phone in it.
func (e *Engine) joinConference(req *sip.Request, tx sip.ServerTransaction, caller *store.Extension, room *store.Room) {
	respond := func(code int, reason string) {
		tx.Respond(sip.NewResponseFromRequest(req, code, reason, nil))
	}
	offer, err := sdp.Parse(req.Body())
	if err != nil {
		respond(488, "Not Acceptable Here")
		return
	}
	if caller.RequireTLS && !offer.Secure {
		respond(488, "SRTP Required")
		return
	}
	// The mixer works in G.711, which every phone supports; the answer
	// only offers that.
	if !containsInt(offer.Formats, 0) && !containsInt(offer.Formats, 8) {
		e.log.Warn("conference refused: phone offered no G.711", "caller", caller.Number, "room", room.Number)
		respond(488, "Not Acceptable Here")
		return
	}

	leg := &confLeg{id: newCallID(), caller: caller, room: room, started: time.Now()}
	leg.log = e.log.With("call", leg.id, "caller", caller.Number, "room", room.Number)
	respond(100, "Trying")

	ds, err := e.uaFor(req.Transport()).ReadInvite(req, tx)
	if err != nil {
		leg.log.Error("read invite", "error", err)
		respond(500, "Server Error")
		return
	}
	leg.ds = ds
	if leg.ep, err = media.NewEndpoint(e.ports, leg.log); err != nil {
		leg.log.Error("conference media", "error", err)
		ds.Respond(503, "Service Unavailable", nil)
		return
	}
	leg.ep.SetRemote(offer, sipauth.SourceIP(req))
	var sid [8]byte
	rand.Read(sid[:])
	leg.local = sdp.Local{IP: e.publicIP, Port: leg.ep.Port, PT: offer.G711(), DTMF: offer.DTMF,
		SessionID: binary.BigEndian.Uint64(sid[:]) >> 1, Version: 1}
	if err := leg.applyOffer(offer); err != nil {
		leg.log.Warn("unusable SRTP offer", "error", err)
		leg.ep.Close()
		ds.Respond(488, "Not Acceptable Here", nil)
		return
	}
	answer := sdp.Build(leg.local)

	leg.p = conference.NewParticipant(leg.ep, leg.id, caller.Number, caller.Name, room.Number,
		offer.DTMF, room.PIN, func(reason string) { e.endConference(leg, "system", reason, true) })
	e.mu.Lock()
	e.confByA[ds.ID] = leg
	e.mu.Unlock()

	// Blocks until the phone ACKs (HandleAck).
	if err := ds.Respond(200, "OK", answer,
		sip.NewHeader("Content-Type", "application/sdp"),
		sip.NewHeader("Allow", AllowMethods)); err != nil {
		leg.log.Warn("caller did not confirm answer", "error", err)
		e.mu.Lock()
		delete(e.confByA, ds.ID)
		e.mu.Unlock()
		leg.ep.Close()
		return
	}
	e.conf.Join(leg.p)
}

// applyOffer updates codec and keys from SDP the phone sent (initial INVITE
// or re-INVITE) and prepares the PBX's matching answer in leg.local.
func (l *confLeg) applyOffer(offer *sdp.Info) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if offer.Secure {
		if len(offer.Cryptos) == 0 {
			return errNoUsableCrypto
		}
		phone := offer.Cryptos[0]
		if l.ours == nil || l.ours.Suite != phone.Suite {
			ours, err := sdp.NewCrypto(phone.Tag, phone.Suite)
			if err != nil {
				return err
			}
			l.ours = ours
		} else {
			cp := *l.ours
			cp.Tag = phone.Tag
			l.ours = &cp
		}
		if err := l.ep.SetCrypto(phone, l.ours); err != nil {
			return err
		}
		l.local.Crypto = l.ours
	} else {
		l.ep.SetCrypto(nil, nil)
		l.local.Crypto = nil
	}
	// Switch G.711 flavor only if the phone dropped the current one.
	if !containsInt(offer.Formats, l.local.PT) && (containsInt(offer.Formats, 0) || containsInt(offer.Formats, 8)) {
		l.local.PT = offer.G711()
	}
	l.ep.SetPayloadType(l.local.PT)
	if offer.DTMF >= 0 {
		l.local.DTMF = offer.DTMF
	}
	l.local.Direction = sdp.AnswerDirection(offer.Direction)
	return nil
}

// endConference takes a phone out of its room. bye is true when the PBX
// hangs up (media timeout, wrong PIN) rather than the phone.
func (e *Engine) endConference(l *confLeg, by, reason string, bye bool) {
	l.endOnce.Do(func() {
		// Out of the room first, so no audio reaches the phone after its BYE.
		e.conf.Leave(l.p)
		if bye {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := l.ds.Bye(ctx); err != nil {
				l.log.Debug("bye to conference phone", "error", err)
			}
			cancel()
		}
		e.mu.Lock()
		delete(e.confByA, l.ds.ID)
		e.mu.Unlock()
		enc := store.EncryptionNone
		if l.ep.Secure() {
			enc = store.EncryptionFull
		}
		rec := &store.CallRecord{ID: l.id, Caller: l.caller.Number, Callee: l.room.Number,
			Status: store.CallAnswered, HangupBy: by, StartedAt: l.started, AnsweredAt: l.started,
			EndedAt: time.Now(), Encryption: enc}
		if err := e.store.SaveCall(context.Background(), rec); err != nil {
			l.log.Error("save call record", "error", err)
		}
		attrs := []any{"hangup_by", by, "duration", rec.Duration().Round(time.Second)}
		if reason != "" {
			attrs = append(attrs, "reason", reason)
		}
		l.log.Info("conference call ended", attrs...)
	})
}

func (e *Engine) lookupConf(req *sip.Request) *confLeg {
	id, err := sip.DialogIDFromRequestUAS(req)
	if err != nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.confByA[id]
}

// confInDialog handles requests inside a conference call: re-INVITE/UPDATE
// (hold, refresh, key changes) are answered by the PBX, INFO may carry keypad
// digits for the PIN.
func (e *Engine) confInDialog(l *confLeg, req *sip.Request, tx sip.ServerTransaction) {
	switch req.Method {
	case sip.INVITE, sip.UPDATE:
		if body := req.Body(); len(body) > 0 {
			offer, err := sdp.Parse(body)
			if err == nil {
				l.ep.SetRemote(offer, sipauth.SourceIP(req))
				err = l.applyOffer(offer)
			}
			if err != nil {
				tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
				return
			}
			l.mu.Lock()
			l.local.Version++
			l.mu.Unlock()
		}
		l.mu.Lock()
		answer := sdp.Build(l.local)
		l.mu.Unlock()
		res := sip.NewResponseFromRequest(req, 200, "OK", answer)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		contact := e.uaFor(req.Transport()).ContactHDR
		res.AppendHeader(&contact)
		tx.Respond(res)
	case sip.INFO:
		if d, ok := infoDigit(req); ok {
			l.p.Digit(d)
		}
		tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	default:
		tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

// infoDigit extracts a keypad digit from a SIP INFO (application/dtmf-relay
// "Signal=5" or application/dtmf "5").
func infoDigit(req *sip.Request) (byte, bool) {
	body := strings.TrimSpace(string(req.Body()))
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(strings.ToLower(line), "signal="); ok {
			body = strings.TrimSpace(v)
			break
		}
	}
	if len(body) == 1 && strings.ContainsRune("0123456789*#", rune(body[0])) {
		return body[0], true
	}
	return 0, false
}

// Conferences lists active rooms and their participants.
func (e *Engine) Conferences() []conference.RoomStatus { return e.conf.Status() }

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
