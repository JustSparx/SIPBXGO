package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/JustSparx/SIPBXGO/internal/store"
)

func roomCmd(st *store.Store, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	ctx := context.Background()
	sub, args := args[0], args[1:]
	number, args := splitPositional(args)

	switch sub {
	case "add", "set":
		fs := flag.NewFlagSet("room "+sub, flag.ContinueOnError)
		name := fs.String("name", "", "display name")
		pin := fs.String("pin", "", "PIN callers must key (digits)")
		noPIN := fs.Bool("no-pin", false, "remove the PIN")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if number == "" {
			return errUsage
		}
		if sub == "add" {
			if err := st.CreateRoom(ctx, &store.Room{Number: number, Name: *name, PIN: *pin}); err != nil {
				return err
			}
			fmt.Printf("Created conference room %s\n", number)
			return nil
		}
		r, err := st.GetRoom(ctx, number)
		if err != nil {
			return err
		}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "name":
				r.Name = *name
			case "pin":
				r.PIN = *pin
			}
		})
		if *noPIN {
			r.PIN = ""
		}
		if err := st.UpdateRoom(ctx, r); err != nil {
			return err
		}
		fmt.Printf("Updated conference room %s\n", number)
		return nil

	case "list":
		rooms, err := st.ListRooms(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ROOM\tNAME\tPIN")
		for _, r := range rooms {
			pin := "-"
			if r.PIN != "" {
				pin = r.PIN
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Number, r.Name, pin)
		}
		return w.Flush()

	case "del", "delete", "rm":
		if number == "" {
			return errUsage
		}
		if err := st.DeleteRoom(ctx, number); err != nil {
			return err
		}
		fmt.Printf("Deleted conference room %s\n", number)
		return nil
	}
	return errUsage
}
