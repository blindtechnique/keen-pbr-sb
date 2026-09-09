package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type desiredStateTransport struct {
	tag     string
	downErr error
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
