// Package tlscert supplies the certificate for SIP over TLS and keeps it
// fresh: it can read a PEM cert/key pair, or share the Let's Encrypt
// certificate Traefik already maintains in its acme.json. Either way the
// source is re-read when it changes, so renewals need no restart.
package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// Loader holds the current certificate and reloads it when its source file
// changes.
type Loader struct {
	source string // human description, for logs/UI
	path   string // file whose modification time signals a change
	load   func() (*tls.Certificate, error)
	log    *slog.Logger

	mu      sync.RWMutex
	cert    *tls.Certificate
	modTime time.Time
}

// FromFiles loads a PEM certificate chain and private key.
func FromFiles(certPath, keyPath string, log *slog.Logger) *Loader {
	return &Loader{
		source: certPath,
		path:   certPath,
		log:    log,
		load: func() (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certPath, keyPath)
			return &c, err
		},
	}
}

// FromTraefik reads the certificate for domain out of Traefik's acme.json.
// A wildcard certificate (*.example.com) also matches.
func FromTraefik(acmePath, domain string, log *slog.Logger) *Loader {
	return &Loader{
		source: "Traefik " + acmePath,
		path:   acmePath,
		log:    log,
		load:   func() (*tls.Certificate, error) { return loadTraefik(acmePath, domain) },
	}
}

// Static serves a fixed certificate (tests, or a self-signed fallback).
func Static(c *tls.Certificate, source string) *Loader {
	l := &Loader{source: source, load: func() (*tls.Certificate, error) { return c, nil }}
	l.cert = c
	return l
}

// Load reads the certificate now; call once at startup to fail fast.
func (l *Loader) Load() error {
	var mod time.Time
	if l.path != "" {
		st, err := os.Stat(l.path)
		if err != nil {
			return err
		}
		mod = st.ModTime()
	}
	c, err := l.load()
	if err != nil {
		return err
	}
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = leaf
		}
	}
	l.mu.Lock()
	l.cert, l.modTime = c, mod
	l.mu.Unlock()
	return nil
}

// GetCertificate is for tls.Config.GetCertificate.
func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.cert == nil {
		return nil, errors.New("tlscert: no certificate loaded")
	}
	return l.cert, nil
}

// TLSConfig returns a server config using this loader.
func (l *Loader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: l.GetCertificate,
	}
}

// Info describes the current certificate for display.
type Info struct {
	Source   string
	Names    []string
	NotAfter time.Time
}

func (l *Loader) Info() Info {
	l.mu.RLock()
	defer l.mu.RUnlock()
	i := Info{Source: l.source}
	if l.cert != nil && l.cert.Leaf != nil {
		i.Names = l.cert.Leaf.DNSNames
		i.NotAfter = l.cert.Leaf.NotAfter
	}
	return i
}

// Watch re-reads the source whenever its file changes, until ctx ends.
func (l *Loader) Watch(ctx context.Context, every time.Duration) {
	if l.path == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := os.Stat(l.path)
			if err != nil {
				continue
			}
			l.mu.RLock()
			changed := !st.ModTime().Equal(l.modTime)
			l.mu.RUnlock()
			if !changed {
				continue
			}
			if err := l.Load(); err != nil {
				// Keep serving the old certificate.
				l.log.Error("TLS certificate reload failed", "source", l.source, "error", err)
				continue
			}
			l.log.Info("TLS certificate reloaded", "source", l.source, "expires", l.Info().NotAfter.Format(time.DateOnly))
		}
	}
}

// Traefik's acme.json: one entry per certificate resolver.
type acmeFile map[string]struct {
	Certificates []struct {
		Domain struct {
			Main string   `json:"main"`
			SANs []string `json:"sans"`
		} `json:"domain"`
		Certificate string `json:"certificate"` // base64 of PEM chain
		Key         string `json:"key"`         // base64 of PEM key
	} `json:"Certificates"`
}

func loadTraefik(path, domain string) (*tls.Certificate, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("%w (Traefik keeps acme.json root-only: run the container as root, see docker-compose.override.example.yml)", err)
	}
	if err != nil {
		return nil, err
	}
	var f acmeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, resolver := range f {
		for _, c := range resolver.Certificates {
			names := append([]string{c.Domain.Main}, c.Domain.SANs...)
			if !matchesAny(domain, names) {
				continue
			}
			certPEM, err1 := base64.StdEncoding.DecodeString(c.Certificate)
			keyPEM, err2 := base64.StdEncoding.DecodeString(c.Key)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("%s: certificate for %s is not valid base64", path, domain)
			}
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, fmt.Errorf("%s: certificate for %s: %w", path, domain, err)
			}
			return &pair, nil
		}
	}
	return nil, fmt.Errorf("%s has no certificate for %s (is Traefik routing that hostname?)", path, domain)
}

func matchesAny(domain string, names []string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, n := range names {
		n = strings.ToLower(n)
		if n == domain {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.IndexByte(domain, '.'); i > 0 && domain[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// SelfSigned makes a throwaway certificate for hosts (tests and local use).
func SelfSigned(hosts ...string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
