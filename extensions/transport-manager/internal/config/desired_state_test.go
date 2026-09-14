package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type desiredStateTransport struct {
	tag     string
	downErr error
}

type lifecycleCountedTransport struct {
	desiredStateTransport
	upCalls, downCalls int
}

func (f *lifecycleCountedTransport) Up(context.Context) error {
	f.upCalls++
	return nil
}

func (f *lifecycleCountedTransport) Down(context.Context) error {
	f.downCalls++
	return nil
}

func TestSubscriptionUpdateAndSequentialDeletesPreserveDisabledNodeOnReload(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{APIKey: "test-secret", SingBoxBinary: "sing-box", RuntimeDir: t.TempDir()}
	for i, tag := range []string{"disabled", "healthy", "unused_one", "unused_two"} {
		cfg.Transports = append(cfg.Transports, transport.TransportSpec{
			Tag: tag, Type: "sing-box", Interface: "pbr" + string(rune('1'+i)),
			Link: "trojan://test@example.invalid:443", AutoStart: tag == "healthy",
		})
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	fakes := map[string]*lifecycleCountedTransport{}
	for _, spec := range cfg.Transports {
		fake := &lifecycleCountedTransport{desiredStateTransport: desiredStateTransport{tag: spec.Tag}}
		fakes[spec.Tag] = fake
		if err := manager.Add(fake); err != nil {
			t.Fatal(err)
		}
		supervisor.Register(spec)
	}
	if err := supervisor.Up(ctx, "healthy"); err != nil {
		t.Fatal(err)
	}
	admin := NewAdmin(path, cfg, manager, supervisor)
	updated := cfg.Transports[0]
	updated.Link = "trojan://new-credential@updated.example.invalid:8443"
	if err := admin.Update(ctx, "disabled", updated); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"unused_one", "unused_two"} {
		if err := admin.Delete(ctx, tag); err != nil {
			t.Fatal(err)
		}
		status, err := supervisor.Status(ctx, "disabled")
		if err != nil || status.DesiredUp || status.State != transport.StateDown {
			t.Fatalf("unrelated deletion enabled the subscription node: %#v, %v", status, err)
		}
	}
	if fakes["healthy"].upCalls != 1 || fakes["healthy"].downCalls != 0 {
		t.Fatalf("unrelated changes restarted the healthy sibling: %#v", fakes["healthy"])
	}
	stored, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Transports, []transport.TransportSpec{updated, cfg.Transports[1]}) {
		t.Fatalf("persisted inventory changed unrelated preferences: %#v", stored.Transports)
	}
	// Start with a fresh supervisor and reload from disk: no old in-memory
	// desired state is available to accidentally make this assertion pass.
	reloaded := transport.NewSupervisor(transport.NewManager())
	for _, spec := range stored.Transports {
		reloaded.Register(spec)
	}
	desired, exists := reloaded.Forget("disabled")
	if !exists || desired {
		t.Fatal("configuration reload restored a disabled subscription as enabled")
	}
}

func (f *desiredStateTransport) Tag() string                { return f.tag }
func (f *desiredStateTransport) Up(context.Context) error   { return nil }
func (f *desiredStateTransport) Down(context.Context) error { return f.downErr }
func (f *desiredStateTransport) Status(context.Context) transport.Status {
	return transport.Status{Tag: f.tag, Type: "sing-box", State: transport.StateDown}
}

func failNextDesiredStateSave(t *testing.T) {
	t.Helper()
	previous := defaultSaveOperations
	t.Cleanup(func() { defaultSaveOperations = previous })
	first := true
	defaultSaveOperations.syncDirectory = func(directory string) error {
		if first {
			first = false
			return errors.New("injected save sync failure")
		}
		return previous.syncDirectory(directory)
	}
}

func TestIsolatedUpdatePreservesManualDesiredState(t *testing.T) {
	for _, test := range []struct {
		name                                           string
		autoStart, desired, nextAutoStart, nextDesired bool
	}{
		{"manually_stopped", true, false, true, false},
		{"manually_started", false, true, false, true},
		{"explicit_enable", false, false, true, true},
		{"explicit_disable", true, true, false, false},
	} {
		for _, failure := range []string{"none", "remove", "save"} {
			t.Run(test.name+"/"+failure, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "transports.json")
				spec := transport.TransportSpec{Tag: "proxy", Type: "sing-box", Interface: "pbr0",
					Link: "trojan://old@example.invalid:443", AutoStart: test.autoStart}
				cfg := Config{APIKey: "secret", SingBoxBinary: "sing-box", RuntimeDir: t.TempDir(),
					Transports: []transport.TransportSpec{spec}}
				if err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				manager := transport.NewManager()
				fake := &desiredStateTransport{tag: spec.Tag}
				if err := manager.Add(fake); err != nil {
					t.Fatal(err)
				}
				supervisor := transport.NewSupervisor(manager)
				supervisor.Register(spec)
				if test.desired {
					if err := supervisor.Up(context.Background(), spec.Tag); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := supervisor.Down(context.Background(), spec.Tag); err != nil {
						t.Fatal(err)
					}
				}
				admin := NewAdmin(path, cfg, manager, supervisor)
				revision := admin.Revision()
				if failure == "remove" {
					fake.downErr = errors.New("injected remove failure")
				}
				if failure == "save" {
					failNextDesiredStateSave(t)
				}
				next := spec
				next.Link = "trojan://updated@changed.invalid:8443"
				next.AutoStart = test.nextAutoStart
				err := admin.Update(context.Background(), spec.Tag, next)
				if (err != nil) != (failure != "none") {
					t.Fatalf("failure=%s update error=%v", failure, err)
				}
				expectedDesired, expectedSpec := test.nextDesired, next
				if failure != "none" {
					expectedDesired, expectedSpec = test.desired, spec
				}
				status, err := supervisor.Status(context.Background(), spec.Tag)
				if err != nil || status.DesiredUp != expectedDesired {
					t.Fatalf("desired=%v expected=%v error=%v", status.DesiredUp, expectedDesired, err)
				}
				stored, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(stored.Transports) != 1 || stored.Transports[0].Link != expectedSpec.Link || stored.Transports[0].AutoStart != expectedSpec.AutoStart {
					t.Fatalf("persistent config does not match update outcome: %#v", stored.Transports)
				}
				if failure != "none" && admin.Revision() != revision {
					t.Fatal("failed update changed revision")
				}
			})
		}
	}
}

func TestIsolatedFailedDeletePreservesManualDesiredState(t *testing.T) {
	for _, desired := range []bool{false, true} {
		name := "manually_stopped"
		if desired {
			name = "manually_started"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "transports.json")
			spec := transport.TransportSpec{Tag: "proxy", Type: "sing-box", Interface: "pbr0",
				Link: "trojan://old@example.invalid:443", AutoStart: !desired}
			cfg := Config{APIKey: "secret", SingBoxBinary: "sing-box", RuntimeDir: t.TempDir(), Transports: []transport.TransportSpec{spec}}
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			manager := transport.NewManager()
			if err := manager.Add(&desiredStateTransport{tag: spec.Tag}); err != nil {
				t.Fatal(err)
			}
			supervisor := transport.NewSupervisor(manager)
			supervisor.RegisterWithDesired(spec, desired)
			admin := NewAdmin(path, cfg, manager, supervisor)
			failNextDesiredStateSave(t)
			if err := admin.Delete(context.Background(), spec.Tag); err == nil {
				t.Fatal("expected delete failure")
			}
			status, err := supervisor.Status(context.Background(), spec.Tag)
			if err != nil || status.DesiredUp != desired {
				t.Fatalf("desired=%v expected=%v error=%v", status.DesiredUp, desired, err)
			}
			stored, err := Load(path)
			if err != nil || len(stored.Transports) != 1 {
				t.Fatalf("failed delete lost persisted transport: %#v error=%v", stored.Transports, err)
			}
		})
	}
}
