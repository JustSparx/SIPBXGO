package web

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/conference"
	"github.com/JustSparx/SIPBXGO/internal/security"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/JustSparx/SIPBXGO/internal/tlscert"
)

// ---- shared view models ----

type callRow struct {
	Caller, CallerName string
	Callee, CalleeName string
	Answered           time.Time
	Held               bool
	CallerPkts         uint64
	CalleePkts         uint64
	Encryption         string
}

// Audio summarizes media flow: "both", "none", or which phone is silent.
// One silent side almost always means NAT/firewall trouble on that side.
func (c callRow) Audio() string {
	switch {
	case c.CallerPkts > 0 && c.CalleePkts > 0:
		return "both"
	case c.CallerPkts == 0 && c.CalleePkts == 0:
		return "none"
	case c.CallerPkts == 0:
		return "No audio from " + c.Caller
	default:
		return "No audio from " + c.Callee
	}
}

type phoneRow struct {
	*store.Registration
	Name   string
	InCall bool
}

// snapshot gathers live state shared by several pages.
type snapshot struct {
	exts   []*store.Extension
	names  map[string]string
	regs   []*store.Registration
	calls  []callRow
	inCall map[string]bool
	phones map[string]int
}

func (s *Server) snapshot(r *http.Request) (*snapshot, error) {
	ctx := r.Context()
	exts, err := s.store.ListExtensions(ctx)
	if err != nil {
		return nil, err
	}
	regs, err := s.store.ListRegistrations(ctx, "")
	if err != nil {
		return nil, err
	}
	sn := &snapshot{exts: exts, regs: regs, names: map[string]string{}, inCall: map[string]bool{}, phones: map[string]int{}}
	for _, e := range exts {
		sn.names[e.Number] = e.Name
	}
	for _, r := range regs {
		sn.phones[r.Extension]++
	}
	for _, c := range s.pbx.ActiveCalls() {
		a, b := c.Packets()
		sn.calls = append(sn.calls, callRow{
			Caller: c.Caller, CallerName: sn.names[c.Caller],
			Callee: c.Callee, CalleeName: sn.names[c.Callee],
			Answered: c.Answered, Held: c.OnHold(), CallerPkts: a, CalleePkts: b,
			Encryption: c.Encryption(),
		})
		sn.inCall[c.Caller], sn.inCall[c.Callee] = true, true
	}
	sort.Slice(sn.calls, func(i, j int) bool { return sn.calls[i].Answered.Before(sn.calls[j].Answered) })
	return sn, nil
}

// ---- dashboard ----

type dashData struct {
	Rooms      []conference.RoomStatus
	RoomNames  map[string]string
	Extensions int
	PhonesOn   int
	ExtsOn     int
	Bans       int
	Calls      []callRow
	Phones     []phoneRow
	Offline    []*store.Extension
}

func (s *Server) dashData(r *http.Request) (*dashData, error) {
	sn, err := s.snapshot(r)
	if err != nil {
		return nil, err
	}
	d := &dashData{Extensions: len(sn.exts), PhonesOn: len(sn.regs), ExtsOn: len(sn.phones),
		Bans: len(s.pbx.Bans()), Calls: sn.calls, Rooms: s.pbx.Conferences(), RoomNames: map[string]string{}}
	if len(d.Rooms) > 0 {
		rooms, err := s.store.ListRooms(r.Context())
		if err != nil {
			return nil, err
		}
		for _, rm := range rooms {
			d.RoomNames[rm.Number] = rm.Name
		}
	}
	for _, reg := range sn.regs {
		d.Phones = append(d.Phones, phoneRow{Registration: reg, Name: sn.names[reg.Extension], InCall: sn.inCall[reg.Extension]})
	}
	for _, e := range sn.exts {
		if sn.phones[e.Number] == 0 {
			d.Offline = append(d.Offline, e)
		}
	}
	return d, nil
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.dashData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "dashboard", d)
}

func (s *Server) dashboardLive(w http.ResponseWriter, r *http.Request) {
	d, err := s.dashData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderPart(w, r, "dashboard", "live", d)
}

// ---- extensions ----

type extRow struct {
	*store.Extension
	Phones int
	InCall bool
}

type extsData struct {
	Rows  []extRow
	Form  struct{ Number, Name string }
	Error string
}

func (s *Server) extsData(r *http.Request) (*extsData, error) {
	sn, err := s.snapshot(r)
	if err != nil {
		return nil, err
	}
	d := &extsData{}
	for _, e := range sn.exts {
		d.Rows = append(d.Rows, extRow{Extension: e, Phones: sn.phones[e.Number], InCall: sn.inCall[e.Number]})
	}
	return d, nil
}

func (s *Server) extensions(w http.ResponseWriter, r *http.Request) {
	d, err := s.extsData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "extensions", d)
}

func (s *Server) createExtension(w http.ResponseWriter, r *http.Request) {
	number := strings.TrimSpace(r.FormValue("number"))
	name := strings.TrimSpace(r.FormValue("name"))
	secret := r.FormValue("secret")
	fail := func(msg string) {
		d, err := s.extsData(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Error, d.Form.Number, d.Form.Name = msg, number, name
		s.render(w, r, http.StatusBadRequest, "extensions", d)
	}
	if err := store.ValidateNumber(number); err != nil {
		fail("Extension numbers are 2 to 8 digits.")
		return
	}
	if secret == "" {
		secret = store.GenerateSecret()
	} else if len(secret) < 8 {
		fail("Passwords must be at least 8 characters (or leave it blank to generate one).")
		return
	}
	err := s.store.CreateExtension(r.Context(), &store.Extension{Number: number, Name: name, Secret: secret, Enabled: true})
	if errors.Is(err, store.ErrExists) {
		fail("Extension " + number + " already exists.")
		return
	}
	if errors.Is(err, store.ErrNumberTaken) {
		fail(number + " is already a conference room number.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("extension created", "ext", number, "by", adminFrom(r))
	http.Redirect(w, r, "/extensions/"+number+"?ok=created", http.StatusSeeOther)
}

type extData struct {
	Ext     *store.Extension
	Phones  []*store.Registration
	Calls   []*store.CallRecord
	InCall  bool
	Server  string
	Port    int
	TLSPort int
	Created bool
	Error   string
}

func (s *Server) extData(r *http.Request) (*extData, error) {
	ctx := r.Context()
	number := r.PathValue("number")
	ext, err := s.store.GetExtension(ctx, number)
	if err != nil {
		return nil, err
	}
	regs, err := s.store.ListRegistrations(ctx, number)
	if err != nil {
		return nil, err
	}
	calls, err := s.store.ListCalls(ctx, number, 8, 0)
	if err != nil {
		return nil, err
	}
	server := s.cfg.SIPDomain
	if server == "" {
		server = s.pbx.PublicIP().String()
	}
	d := &extData{Ext: ext, Phones: regs, Calls: calls, Server: server, Port: s.pbx.SIPPort(),
		TLSPort: s.pbx.TLSPort(), Created: r.URL.Query().Get("ok") == "created"}
	for _, c := range s.pbx.ActiveCalls() {
		if c.Caller == number || c.Callee == number {
			d.InCall = true
		}
	}
	return d, nil
}

func (s *Server) extension(w http.ResponseWriter, r *http.Request) {
	d, err := s.extData(r)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/extensions?ok=noextfound", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "extension", d)
}

func (s *Server) extensionLive(w http.ResponseWriter, r *http.Request) {
	d, err := s.extData(r)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.renderPart(w, r, "extension", "live", d)
}

func (s *Server) updateExtension(w http.ResponseWriter, r *http.Request) {
	ext, err := s.store.GetExtension(r.Context(), r.PathValue("number"))
	if err != nil {
		http.Redirect(w, r, "/extensions?ok=noextfound", http.StatusSeeOther)
		return
	}
	ext.Name = strings.TrimSpace(r.FormValue("name"))
	ext.Enabled = r.FormValue("enabled") == "on"
	ext.RequireTLS = r.FormValue("require_tls") == "on"
	if err := s.store.UpdateExtension(r.Context(), ext); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("extension updated", "ext", ext.Number, "enabled", ext.Enabled, "require_tls", ext.RequireTLS, "by", adminFrom(r))
	http.Redirect(w, r, "/extensions/"+ext.Number+"?ok=saved", http.StatusSeeOther)
}

func (s *Server) resetSecret(w http.ResponseWriter, r *http.Request) {
	ext, err := s.store.GetExtension(r.Context(), r.PathValue("number"))
	if err != nil {
		http.Redirect(w, r, "/extensions?ok=noextfound", http.StatusSeeOther)
		return
	}
	secret := r.FormValue("secret")
	if secret == "" {
		secret = store.GenerateSecret()
	} else if len(secret) < 8 {
		d, err := s.extData(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Error = "Passwords must be at least 8 characters (or leave it blank to generate one)."
		s.render(w, r, http.StatusBadRequest, "extension", d)
		return
	}
	ext.Secret = secret
	if err := s.store.UpdateExtension(r.Context(), ext); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("extension password changed", "ext", ext.Number, "by", adminFrom(r))
	http.Redirect(w, r, "/extensions/"+ext.Number+"?ok=secret", http.StatusSeeOther)
}

func (s *Server) deleteExtension(w http.ResponseWriter, r *http.Request) {
	number := r.PathValue("number")
	if err := s.store.DeleteExtension(r.Context(), number); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("extension deleted", "ext", number, "by", adminFrom(r))
	http.Redirect(w, r, "/extensions?ok=deleted", http.StatusSeeOther)
}

// ---- call history ----

const callsPerPage = 50

type callsData struct {
	Calls   []*store.CallRecord
	Names   map[string]string
	Exts    []*store.Extension
	Filter  string
	Page    int
	HasNext bool
}

func (d *callsData) PageURL(page int) string {
	q := url.Values{}
	if d.Filter != "" {
		q.Set("ext", d.Filter)
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	if len(q) == 0 {
		return "/calls"
	}
	return "/calls?" + q.Encode()
}

func (s *Server) calls(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := &callsData{Filter: r.URL.Query().Get("ext"), Page: 1, Names: map[string]string{}}
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		d.Page = p
	}
	calls, err := s.store.ListCalls(ctx, d.Filter, callsPerPage+1, (d.Page-1)*callsPerPage)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(calls) > callsPerPage {
		d.HasNext, calls = true, calls[:callsPerPage]
	}
	d.Calls = calls
	if d.Exts, err = s.store.ListExtensions(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, e := range d.Exts {
		d.Names[e.Number] = e.Name
	}
	s.render(w, r, http.StatusOK, "calls", d)
}

// ---- security ----

type securityData struct {
	TLS       *tlscert.Info
	TLSPort   int
	Bans      []security.Ban
	Trusted   []netip.Prefix
	Threshold int
	Window    time.Duration
	Duration  time.Duration
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	bans := s.pbx.Bans()
	sort.Slice(bans, func(i, j int) bool { return bans[i].Until.After(bans[j].Until) })
	s.render(w, r, http.StatusOK, "security", &securityData{
		TLS: s.pbx.TLSInfo(), TLSPort: s.pbx.TLSPort(),
		Bans: bans, Trusted: s.cfg.TrustedNets,
		Threshold: s.cfg.BanThreshold, Window: s.cfg.BanWindow, Duration: s.cfg.BanDuration,
	})
}

func (s *Server) unban(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.FormValue("ip"))
	if err != nil {
		http.Error(w, "bad address", http.StatusBadRequest)
		return
	}
	s.pbx.Unban(ip)
	s.log.Info("ip unbanned", "ip", ip, "by", adminFrom(r))
	http.Redirect(w, r, "/security?ok=unbanned", http.StatusSeeOther)
}

// ---- account ----

type accountData struct {
	Admins []*store.Admin
	Error  string
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	admins, err := s.store.ListAdmins(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "account", &accountData{Admins: admins})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := adminFrom(r)
	fail := func(status int, msg string) {
		admins, _ := s.store.ListAdmins(ctx)
		s.render(w, r, status, "account", &accountData{Admins: admins, Error: msg})
	}
	if err := s.store.CheckAdminPassword(ctx, user, r.FormValue("current")); err != nil {
		fail(http.StatusUnauthorized, "Your current password is wrong.")
		return
	}
	next := r.FormValue("new")
	if next != r.FormValue("confirm") {
		fail(http.StatusBadRequest, "The new passwords don't match.")
		return
	}
	if err := s.store.SetAdminPassword(ctx, user, next); err != nil {
		fail(http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	// Changing the password signs out every session; keep this one.
	token, err := s.store.CreateSession(ctx, user, SessionTTL)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", MaxAge: int(SessionTTL.Seconds()),
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
	s.log.Info("admin password changed", "user", user)
	http.Redirect(w, r, "/account?ok=password", http.StatusSeeOther)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
