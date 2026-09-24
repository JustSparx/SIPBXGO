package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// layout is the data every page template receives.
type layout struct {
	Title   string
	Nav     string // active nav item
	Admin   string
	Version string
	Flash   string
	Data    any
}

var pageFiles = map[string]string{
	"login":      "login.html",
	"dashboard":  "dashboard.html",
	"extensions": "extensions.html",
	"extension":  "extension.html",
	"calls":      "calls.html",
	"security":   "security.html",
	"account":    "account.html",
}

var titles = map[string]string{
	"login": "Sign in", "dashboard": "Dashboard", "extensions": "Extensions",
	"extension": "Extension", "calls": "Call history", "security": "Security", "account": "Account",
}

// flashes are success messages selected by ?ok=... after a redirect.
var flashes = map[string]string{
	"created":    "Extension created. Enter these settings into the phone.",
	"saved":      "Changes saved.",
	"secret":     "New password set. Update the phone, or it will stop registering within a few minutes.",
	"deleted":    "Extension deleted.",
	"unbanned":   "Ban lifted.",
	"password":   "Your password was changed. Other sessions were signed out.",
	"noextfound": "That extension no longer exists.",
}

var funcs = template.FuncMap{
	"ago":    ago,
	"clock":  clock,
	"since":  func(t time.Time) time.Duration { return time.Since(t) },
	"until":  func(t time.Time) string { return roundDur(time.Until(t)) },
	"stamp":  func(t time.Time) string { return t.Local().Format("Jan 2, 15:04") },
	"full":   func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST") },
	"status": statusLabel,
	"device": device,
	"add":    func(a, b int) int { return a + b },
	"dur":    roundDur,
	"days":   func(t time.Time) int { return int(time.Until(t).Hours() / 24) },
	"isTLS":  func(tr string) bool { return strings.EqualFold(tr, "TLS") },
	"encLabel": func(e string) string {
		switch e {
		case "full":
			return "Encrypted"
		case "partial":
			return "Partly encrypted"
		case "none":
			return "Not encrypted"
		}
		return ""
	},
	"encClass": func(e string) string {
		switch e {
		case "full":
			return "ok"
		case "partial":
			return "warn"
		}
		return "mute"
	},
	"statusClass": func(s string) string {
		switch s {
		case "answered":
			return "ok"
		case "busy", "no-answer":
			return "warn"
		case "cancelled":
			return "mute"
		}
		return "bad"
	},
}

func (s *Server) parseTemplates() error {
	s.pages = make(map[string]*template.Template)
	for name, file := range pageFiles {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+file)
		if err != nil {
			return fmt.Errorf("template %s: %w", file, err)
		}
		s.pages[name] = t
	}
	return nil
}

// render writes a full page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	s.execute(w, r, status, name, "layout.html", data)
}

// renderPart writes one named block of a page (for live refresh).
func (s *Server) renderPart(w http.ResponseWriter, r *http.Request, name, block string, data any) {
	w.Header().Set("Cache-Control", "no-store")
	s.execute(w, r, http.StatusOK, name, block, data)
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, status int, name, block string, data any) {
	nav := name
	if name == "extension" {
		nav = "extensions"
	}
	l := layout{
		Title:   titles[name],
		Nav:     nav,
		Admin:   adminFrom(r),
		Version: s.version,
		Flash:   flashes[r.URL.Query().Get("ok")],
		Data:    data,
	}
	// Render to a buffer first so a template error doesn't leave half a page.
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, block, l); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("web", "path", r.URL.Path, "error", err)
	http.Error(w, "Something went wrong. Check the server log.", http.StatusInternalServerError)
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// clock formats a call duration like a phone display: 4:05 or 1:02:09.
func clock(d time.Duration) string {
	s := int(d.Seconds())
	if s < 0 {
		s = 0
	}
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s%3600/60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// roundDur formats a duration compactly: 45s, 12m, 3h, 1h30m.
func roundDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Round(time.Second).Seconds()))
	}
	d = d.Round(time.Minute)
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

func statusLabel(s string) string {
	switch s {
	case "no-answer":
		return "No answer"
	case "":
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// device shortens a User-Agent for display.
func device(ua string) string {
	if ua == "" {
		return "Unknown device"
	}
	if len(ua) > 48 {
		return ua[:47] + "…"
	}
	return ua
}
