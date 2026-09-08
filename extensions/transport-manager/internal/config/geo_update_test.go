package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

func TestNativeGeoUpdateMergesCurrentSpecWithoutRuntimeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{APIKey: "secret", RuntimeDir: t.TempDir()}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	admin := NewAdmin(path, cfg, manager, transport.NewSupervisor(manager))
	spec := transport.TransportSpec{Tag: "native_one", Type: "native", Interface: "nwg5", DisplayName: "import name", GeoMode: "auto"}
	if err := admin.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	runtime, _ := manager.Get(spec.Tag)
	request := NativeGeoUpdate{Tag: spec.Tag, ExpectedInterface: spec.Interface, CountryCode: "de", Country: "Germany"}
	spec.DisplayName = "user new name"
	if err := admin.Update(context.Background(), spec.Tag, spec); err != nil {
		t.Fatal(err)
	}
	updated, revision, err := admin.UpdateNativeGeo(context.Background(), request)
	if err != nil || !updated {
		t.Fatalf("geo merge failed: %v", err)
	}
	current := admin.Specs()[0]
	if current.DisplayName != "user new name" || current.GeoMode != "auto" || current.CountryCode != "DE" {
		t.Fatalf("stale fields replayed: %#v", current)
	}
	after, _ := manager.Get(spec.Tag)
	if after != runtime {
		t.Fatal("geo merge replaced runtime transport")
	}
	if updated, next, err := admin.UpdateNativeGeo(context.Background(), request); err != nil || updated || next != revision {
		t.Fatal("identical geo result mutated config")
	}
	for _, mode := range []string{"manual", "disabled"} {
		current.GeoMode, current.CountryCode, current.Country = mode, "FR", "France"
		if err := admin.Update(context.Background(), current.Tag, current); err != nil {
			t.Fatal(err)
		}
		if updated, _, err := admin.UpdateNativeGeo(context.Background(), request); err != nil || updated {
			t.Fatalf("late result changed %s mode", mode)
		}
		if admin.Specs()[0].CountryCode != "FR" {
			t.Fatal("late result overwrote chosen country")
		}
	}
	current.GeoMode = "auto"
	if err := admin.Update(context.Background(), current.Tag, current); err != nil {
		t.Fatal(err)
	}
	request.ExpectedInterface = "nwg6"
	if updated, _, err := admin.UpdateNativeGeo(context.Background(), request); err != nil || updated {
		t.Fatal("late result changed another interface")
	}
	request.ExpectedInterface = current.Interface
	original := defaultSaveOperations
	t.Cleanup(func() { defaultSaveOperations = original })
	defaultSaveOperations.rename = func(string, string) error { return errors.New("injected rename failure") }
	if updated, _, err := admin.UpdateNativeGeo(context.Background(), request); err == nil || updated {
		t.Fatal("failed metadata save reported success")
	}
	if admin.Specs()[0].CountryCode != "FR" {
		t.Fatal("failed metadata save changed in-memory state")
	}
}
