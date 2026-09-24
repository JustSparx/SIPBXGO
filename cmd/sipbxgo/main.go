// Command sipbxgo is a small SIP PBX for extension-to-extension calling.
//
//	sipbxgo serve                         run the PBX
//	sipbxgo ext add 101 -name Kitchen     create an extension (prints its password)
//	sipbxgo ext list                      list extensions
//	sipbxgo reg list                      show registered phones
//	sipbxgo call list                     show call history
//
// Run `sipbxgo help` for everything.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/JustSparx/SIPBXGO/internal/config"
	"github.com/JustSparx/SIPBXGO/internal/pbx"
	"github.com/JustSparx/SIPBXGO/internal/store"
	"github.com/emiago/sipgo/sip"
)

const usage = `SIPBXGO — a small SIP PBX for extension-to-extension calling.

Usage:
  sipbxgo serve                                 Run the PBX
  sipbxgo ext add <number> [-name N] [-secret S] Create an extension (secret generated if omitted)
  sipbxgo ext list [-show-secrets]              List extensions
  sipbxgo ext show <number>                     Show one extension, including its secret
  sipbxgo ext set <number> [-name N] [-secret S] [-new-secret] [-enable|-disable]
  sipbxgo ext del <number>                      Delete an extension
  sipbxgo reg list                              Show registered phones
  sipbxgo call list [-n 20]                     Show recent call history
  sipbxgo version                               Print version

Configuration is read from SIPBX_* environment variables; see README.md.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	switch args[0] {
	case "serve":
		return serve(cfg)
	case "ext":
		return withStore(cfg, func(st *store.Store) error { return extCmd(st, args[1:]) })
	case "reg":
		return withStore(cfg, func(st *store.Store) error { return regCmd(st, args[1:]) })
	case "call", "calls":
		return withStore(cfg, func(st *store.Store) error { return callCmd(st, args[1:]) })
	case "version", "-version", "--version":
		fmt.Println("sipbxgo", pbx.Version)
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `sipbxgo help`)", args[0])
	}
}

func openStore(cfg *config.Config) (*store.Store, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(cfg.DataDir, "sipbxgo.db"))
}

func withStore(cfg *config.Config, f func(*store.Store) error) error {
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	return f(st)
}

func serve(cfg *config.Config) error {
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	sip.SIPDebug = os.Getenv("SIPBX_SIP_DEBUG") != ""

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	exts, err := st.ListExtensions(context.Background())
	if err != nil {
		return err
	}
	if len(exts) == 0 {
		log.Warn("no extensions yet — create one with: sipbxgo ext add 101 -name \"Kitchen\"")
	}

	srv, err := pbx.New(cfg, st, log)
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	if cfg.PublicIP == "" {
		log.Warn("SIPBX_PUBLIC_IP not set; using auto-detected address — set it if phones can't hear each other",
			"detected", srv.PublicIP())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting sipbxgo", "version", pbx.Version, "data_dir", cfg.DataDir, "extensions", len(exts))
	err = srv.Serve(ctx)
	log.Info("stopped")
	return err
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// splitPositional lets users write `ext add 101 -name X` as well as
// `ext add -name X 101`: Go's flag package stops at the first non-flag.
func splitPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

var errUsage = errors.New("invalid arguments (try `sipbxgo help`)")
