package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestExtensionCRUD(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	e := &Extension{Number: "101", Name: "Kitchen", Secret: "pw", Enabled: true}
	if err := st.CreateExtension(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateExtension(ctx, e); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: got %v", err)
	}
	if err := st.CreateExtension(ctx, &Extension{Number: "1", Secret: "x"}); err == nil {
		t.Fatal("1-digit extension accepted")
	}

	got, err := st.GetExtension(ctx, "101")
	if err != nil || got.Name != "Kitchen" || got.Secret != "pw" || !got.Enabled {
		t.Fatalf("get: %+v %v", got, err)
	}

	got.Name, got.Enabled = "Garage", false
	if err := st.UpdateExtension(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetExtension(ctx, "101")
	if got.Name != "Garage" || got.Enabled {
		t.Fatalf("update not saved: %+v", got)
	}

	st.CreateExtension(ctx, &Extension{Number: "1000", Secret: "x", Enabled: true})
	st.CreateExtension(ctx, &Extension{Number: "102", Secret: "x", Enabled: true})
	list, _ := st.ListExtensions(ctx)
	if len(list) != 3 || list[0].Number != "101" || list[1].Number != "102" || list[2].Number != "1000" {
		t.Fatalf("list order wrong: %v %v %v", list[0].Number, list[1].Number, list[2].Number)
	}

	if err := st.DeleteExtension(ctx, "101"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetExtension(ctx, "101"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestRegistrations(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	st.CreateExtension(ctx, &Extension{Number: "101", Secret: "pw", Enabled: true})

	now := time.Now()
	r := &Registration{Extension: "101", Contact: "sip:101@192.168.1.5:5060", Source: "203.0.113.1:40000",
		Transport: "UDP", ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	if err := st.SaveRegistration(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Refresh from a new NAT port: same contact, updated source.
	r.Source = "203.0.113.1:40001"
	if err := st.SaveRegistration(ctx, r); err != nil {
		t.Fatal(err)
	}
	regs, _ := st.ListRegistrations(ctx, "101")
	if len(regs) != 1 || regs[0].Source != "203.0.113.1:40001" {
		t.Fatalf("upsert failed: %+v", regs)
	}

	expired := *r
	expired.Contact = "sip:101@10.0.0.9"
	expired.ExpiresAt = now.Add(-time.Second)
	st.SaveRegistration(ctx, &expired)
	if regs, _ := st.ListRegistrations(ctx, ""); len(regs) != 1 {
		t.Fatalf("expired binding listed: %d", len(regs))
	}
	if n, _ := st.PurgeExpiredRegistrations(ctx); n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}

	// Deleting the extension cascades to its bindings.
	st.DeleteExtension(ctx, "101")
	if regs, _ := st.ListRegistrations(ctx, ""); len(regs) != 0 {
		t.Fatal("bindings survived extension delete")
	}
}
