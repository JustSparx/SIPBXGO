package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/JustSparx/SIPBXGO/internal/store"
)

const sessionCookie = "sipbxgo_session"

type ctxKey struct{}

// adminFrom returns the logged-in admin's username.
func adminFrom(r *http.Request) string {
	u, _ := r.Context().Value(ctxKey{}).(string)
	return u
}

// requireLogin lets the request through only with a valid session. Pages
// redirect to /login; live-refresh fetches get 401 so the page reloads.
func (s *Server) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			user, err := s.store.SessionUser(r.Context(), c.Value)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
				return
			}
			if !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/live/") || r.Method != http.MethodGet {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	})
}

// safeNext only allows redirects back into this site.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

type loginData struct {
	Next     string
	Username string
	Error    string
	NoAdmins bool
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	admins, _ := s.store.ListAdmins(r.Context())
	s.render(w, r, http.StatusOK, "login", loginData{Next: safeNext(r.URL.Query().Get("next")), NoAdmins: len(admins) == 0})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	data := loginData{Next: safeNext(r.FormValue("next")), Username: r.FormValue("username")}
	if s.loginLimit.IsBanned(ip) {
		data.Error = "Too many failed attempts. Try again in 15 minutes."
		s.render(w, r, http.StatusTooManyRequests, "login", data)
		return
	}
	err := s.store.CheckAdminPassword(r.Context(), data.Username, r.FormValue("password"))
	if errors.Is(err, store.ErrBadLogin) {
		s.log.Warn("web login failed", "ip", ip, "user", data.Username)
		if s.loginLimit.Fail(ip) {
			s.log.Warn("web login locked out", "ip", ip)
		}
		data.Error = "Wrong username or password."
		s.render(w, r, http.StatusUnauthorized, "login", data)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loginLimit.Succeed(ip)
	token, err := s.store.CreateSession(r.Context(), data.Username, SessionTTL)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	s.log.Info("web login", "ip", ip, "user", data.Username)
	http.Redirect(w, r, data.Next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
