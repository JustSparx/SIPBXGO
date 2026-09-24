package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func pemPair(t *testing.T, hosts ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	c, err := SelfSigned(hosts...)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// writeAcme writes a Traefik-style acme.json holding certs for the given
// main domains.
func writeAcme(t *testing.T, path string, mains ...string) {
	t.Helper()
	type cert struct {
		Domain struct {
			Main string   `json:"main"`
			SANs []string `json:"sans,omitempty"`
		} `json:"domain"`
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
		Store       string `json:"Store"`
	}
	var certs []cert
	for _, m := range mains {
		cp, kp := pemPair(t, m)
		var c cert
		c.Domain.Main = m
		c.Certificate = base64.StdEncoding.EncodeToString(cp)
		c.Key = base64.StdEncoding.EncodeToString(kp)
		c.Store = "default"
		certs = append(certs, c)
	}
	doc := map[string]any{"letsencrypt": map[string]any{"Account": map[string]any{"Email": "x@example.com"}, "Certificates": certs}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFromTraefik(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	writeAcme(t, path, "n8n.example.com", "pbx.example.com", "*.wild.example.com")

	l := FromTraefik(path, "pbx.example.com", quiet)
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	if info := l.Info(); len(info.Names) != 1 || info.Names[0] != "pbx.example.com" || info.NotAfter.IsZero() {
		t.Fatalf("info: %+v", info)
	}
	if err := FromTraefik(path, "sip.wild.example.com", quiet).Load(); err != nil {
		t.Fatalf("wildcard not matched: %v", err)
	}
	if err := FromTraefik(path, "a.b.wild.example.com", quiet).Load(); err == nil {
		t.Fatal("wildcard matched two labels deep")
	}
	if err := FromTraefik(path, "missing.example.com", quiet).Load(); err == nil {
		t.Fatal("missing domain loaded")
	}
}

func TestReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	cp, kp := pemPair(t, "one.example.com")
	os.WriteFile(certPath, cp, 0o600)
	os.WriteFile(keyPath, kp, 0o600)

	l := FromFiles(certPath, keyPath, quiet)
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Watch(ctx, 20*time.Millisecond)

	cp, kp = pemPair(t, "two.example.com")
	os.WriteFile(keyPath, kp, 0o600)
	os.WriteFile(certPath, cp, 0o600)
	future := time.Now().Add(time.Minute) // make sure the mtime visibly changes
	os.Chtimes(certPath, future, future)

	for i := 0; i < 100; i++ {
		if names := l.Info().Names; len(names) == 1 && names[0] == "two.example.com" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("certificate not reloaded: %v", l.Info().Names)
}

func TestServesHandshake(t *testing.T) {
	c, _ := SelfSigned("pbx.example.com")
	l := Static(c, "test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", l.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(c.Leaf)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "pbx.example.com"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	conn.Close()
}
