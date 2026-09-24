package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"text/tabwriter"
	"time"

	"github.com/JustSparx/SIPBXGO/internal/store"
)

func extCmd(st *store.Store, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	ctx := context.Background()
	sub, args := args[0], args[1:]
	number, args := splitPositional(args)

	switch sub {
	case "add":
		fs := flag.NewFlagSet("ext add", flag.ContinueOnError)
		name := fs.String("name", "", "display name")
		secret := fs.String("secret", "", "password (generated if empty)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if number == "" {
			number = fs.Arg(0)
		}
		if number == "" {
			return errUsage
		}
		if *secret == "" {
			*secret = generateSecret()
		}
		e := &store.Extension{Number: number, Name: *name, Secret: *secret, Enabled: true}
		if err := st.CreateExtension(ctx, e); err != nil {
			return err
		}
		fmt.Printf("Created extension %s", e.Number)
		if e.Name != "" {
			fmt.Printf(" (%s)", e.Name)
		}
		fmt.Printf("\n  username: %s\n  password: %s\n", e.Number, e.Secret)
		return nil

	case "list":
		fs := flag.NewFlagSet("ext list", flag.ContinueOnError)
		show := fs.Bool("show-secrets", false, "include passwords")
		if err := fs.Parse(args); err != nil {
			return err
		}
		exts, err := st.ListExtensions(ctx)
		if err != nil {
			return err
		}
		regs, err := st.ListRegistrations(ctx, "")
		if err != nil {
			return err
		}
		online := map[string]int{}
		for _, r := range regs {
			online[r.Extension]++
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprint(w, "EXT\tNAME\tENABLED\tPHONES")
		if *show {
			fmt.Fprint(w, "\tSECRET")
		}
		fmt.Fprintln(w)
		for _, e := range exts {
			fmt.Fprintf(w, "%s\t%s\t%v\t%d", e.Number, e.Name, e.Enabled, online[e.Number])
			if *show {
				fmt.Fprintf(w, "\t%s", e.Secret)
			}
			fmt.Fprintln(w)
		}
		return w.Flush()

	case "show":
		if number == "" {
			return errUsage
		}
		e, err := st.GetExtension(ctx, number)
		if err != nil {
			return err
		}
		fmt.Printf("extension: %s\nname:      %s\nenabled:   %v\nusername:  %s\npassword:  %s\ncreated:   %s\n",
			e.Number, e.Name, e.Enabled, e.Number, e.Secret, e.CreatedAt.Format(time.RFC3339))
		return nil

	case "set":
		fs := flag.NewFlagSet("ext set", flag.ContinueOnError)
		name := fs.String("name", "", "new display name")
		secret := fs.String("secret", "", "new password")
		newSecret := fs.Bool("new-secret", false, "generate a new password")
		enable := fs.Bool("enable", false, "enable the extension")
		disable := fs.Bool("disable", false, "disable the extension")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if number == "" {
			return errUsage
		}
		e, err := st.GetExtension(ctx, number)
		if err != nil {
			return err
		}
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "name" {
				e.Name = *name
			}
		})
		if *secret != "" {
			e.Secret = *secret
		}
		if *newSecret {
			e.Secret = generateSecret()
		}
		if *enable && *disable {
			return fmt.Errorf("-enable and -disable are mutually exclusive")
		}
		if *enable {
			e.Enabled = true
		}
		if *disable {
			e.Enabled = false
		}
		if err := st.UpdateExtension(ctx, e); err != nil {
			return err
		}
		fmt.Printf("Updated extension %s\n", e.Number)
		if *secret != "" || *newSecret {
			fmt.Printf("  password: %s\n", e.Secret)
		}
		return nil

	case "del", "delete", "rm":
		if number == "" {
			return errUsage
		}
		if err := st.DeleteExtension(ctx, number); err != nil {
			return err
		}
		fmt.Printf("Deleted extension %s\n", number)
		return nil
	}
	return errUsage
}

func callCmd(st *store.Store, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errUsage
	}
	fs := flag.NewFlagSet("call list", flag.ContinueOnError)
	limit := fs.Int("n", 20, "number of calls to show")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	calls, err := st.ListCalls(context.Background(), *limit)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STARTED\tFROM\tTO\tSTATUS\tDURATION\tHUNG UP BY")
	for _, c := range calls {
		dur := "-"
		if !c.AnsweredAt.IsZero() {
			dur = c.Duration().Round(time.Second).String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", c.StartedAt.Format("2006-01-02 15:04:05"),
			c.Caller, c.Callee, c.Status, dur, c.HangupBy)
	}
	return w.Flush()
}

func regCmd(st *store.Store, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errUsage
	}
	regs, err := st.ListRegistrations(context.Background(), "")
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EXT\tSOURCE\tTRANSPORT\tEXPIRES IN\tUSER AGENT\tCONTACT")
	for _, r := range regs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Extension, r.Source, r.Transport,
			time.Until(r.ExpiresAt).Round(time.Second), r.UserAgent, r.Contact)
	}
	return w.Flush()
}

// generateSecret returns a 16-character password without look-alike
// characters, since it will often be typed into a phone's keypad or web UI.
func generateSecret() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}
