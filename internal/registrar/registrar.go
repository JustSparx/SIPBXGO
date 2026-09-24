// Package registrar handles SIP REGISTER: it authenticates phones and records
// where each extension can currently be reached.
package registrar

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/sipauth"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo/sip"
)

// Store is the persistence the registrar needs.
type Store interface {
	SaveRegistration(ctx context.Context, r *store.Registration) error
	DeleteRegistration(ctx context.Context, ext, contact string) error
	DeleteRegistrations(ctx context.Context, ext string) error
	ListRegistrations(ctx context.Context, ext string) ([]*store.Registration, error)
}

type Registrar struct {
	Store      Store
	Guard      *sipauth.Guard
	MinExpires int
	MaxExpires int
	Log        *slog.Logger
	now        func() time.Time
}

func New(st Store, guard *sipauth.Guard, minExp, maxExp int, log *slog.Logger) *Registrar {
	return &Registrar{Store: st, Guard: guard, MinExpires: minExp, MaxExpires: maxExp, Log: log, now: time.Now}
}

// defaultExpires applies when a REGISTER carries neither an Expires header
// nor a contact expires param (RFC 3261 §10.2.1.1 suggests 3600).
const defaultExpires = 3600

type binding struct {
	contact *sip.ContactHeader
	expires int
}

// HandleRegister is the sipgo handler for REGISTER.
func (r *Registrar) HandleRegister(req *sip.Request, tx sip.ServerTransaction) {
	ext := r.Guard.Authorize(req, tx)
	if ext == nil {
		return
	}
	ctx := context.Background()

	// A phone may only register its own extension.
	if to := req.To(); to == nil || to.Address.User != ext.Number {
		r.Log.Warn("register for another extension refused", "auth_user", ext.Number, "ip", sipauth.SourceIP(req))
		tx.Respond(sip.NewResponseFromRequest(req, 403, "Forbidden", nil))
		return
	}

	headerExpires := defaultExpires
	if h := req.GetHeader("Expires"); h != nil {
		if n, err := strconv.Atoi(h.Value()); err == nil && n >= 0 {
			headerExpires = n
		}
	}

	// Parse and validate every contact before changing anything, so a bad
	// request never leaves a half-applied update.
	var bindings []binding
	wildcard := false
	for _, h := range req.GetHeaders("Contact") {
		ch, ok := h.(*sip.ContactHeader)
		if !ok {
			tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Contact", nil))
			return
		}
		if ch.Address.Wildcard {
			wildcard = true
			continue
		}
		exp := headerExpires
		if v, ok := ch.Params.Get("expires"); ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Contact Expires", nil))
				return
			}
			exp = n
		}
		if exp > 0 && exp < r.MinExpires {
			res := sip.NewResponseFromRequest(req, 423, "Interval Too Brief", nil)
			res.AppendHeader(sip.NewHeader("Min-Expires", strconv.Itoa(r.MinExpires)))
			tx.Respond(res)
			return
		}
		if exp > r.MaxExpires {
			exp = r.MaxExpires
		}
		bindings = append(bindings, binding{contact: ch, expires: exp})
	}

	// "Contact: *" with Expires: 0 removes every binding (RFC 3261 §10.3 step 6).
	if wildcard {
		if len(bindings) > 0 || headerExpires != 0 {
			tx.Respond(sip.NewResponseFromRequest(req, 400, "Invalid Wildcard", nil))
			return
		}
		if err := r.Store.DeleteRegistrations(ctx, ext.Number); err != nil {
			r.serverError(req, tx, err)
			return
		}
		r.Log.Info("unregistered all", "ext", ext.Number)
	}

	now := r.now()
	ua := ""
	if h := req.GetHeader("User-Agent"); h != nil {
		ua = h.Value()
	}
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}
	// Existing bindings, to log new phones (or moved ones) at info level and
	// routine refreshes at debug.
	known := map[string]string{} // contact -> source
	if len(bindings) > 0 {
		existing, err := r.Store.ListRegistrations(ctx, ext.Number)
		if err != nil {
			r.serverError(req, tx, err)
			return
		}
		for _, reg := range existing {
			known[reg.Contact] = reg.Source
		}
	}

	for _, b := range bindings {
		contact := b.contact.Address.String()
		if b.expires == 0 {
			if err := r.Store.DeleteRegistration(ctx, ext.Number, contact); err != nil {
				r.serverError(req, tx, err)
				return
			}
			r.Log.Info("unregistered", "ext", ext.Number, "contact", contact)
			continue
		}
		reg := &store.Registration{
			Extension: ext.Number,
			Contact:   contact,
			Source:    req.Source(),
			Transport: req.Transport(),
			UserAgent: ua,
			CallID:    callID,
			ExpiresAt: now.Add(time.Duration(b.expires) * time.Second),
			UpdatedAt: now,
		}
		if err := r.Store.SaveRegistration(ctx, reg); err != nil {
			r.serverError(req, tx, err)
			return
		}
		level := slog.LevelDebug
		if src, ok := known[contact]; !ok || src != reg.Source {
			level = slog.LevelInfo
		}
		r.Log.Log(ctx, level, "registered", "ext", ext.Number, "contact", contact,
			"source", reg.Source, "transport", reg.Transport, "expires", b.expires, "user_agent", ua)
	}

	// 200 OK lists every current binding with its remaining lifetime.
	regs, err := r.Store.ListRegistrations(ctx, ext.Number)
	if err != nil {
		r.serverError(req, tx, err)
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	for _, reg := range regs {
		ch := &sip.ContactHeader{Params: sip.NewParams()}
		if err := sip.ParseUri(reg.Contact, &ch.Address); err != nil {
			continue
		}
		remaining := int(reg.ExpiresAt.Sub(now).Seconds())
		if remaining < 0 {
			remaining = 0
		}
		ch.Params.Add("expires", strconv.Itoa(remaining))
		res.AppendHeader(ch)
	}
	// Some phones set their clock from this, and SIP requires the literal "GMT".
	res.AppendHeader(sip.NewHeader("Date", now.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")))
	tx.Respond(res)
}

func (r *Registrar) serverError(req *sip.Request, tx sip.ServerTransaction, err error) {
	r.Log.Error("registrar", "error", err)
	tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Error", nil))
}

// Lookup returns the live bindings for an extension (used to route calls).
func (r *Registrar) Lookup(ctx context.Context, ext string) ([]*store.Registration, error) {
	return r.Store.ListRegistrations(ctx, ext)
}
