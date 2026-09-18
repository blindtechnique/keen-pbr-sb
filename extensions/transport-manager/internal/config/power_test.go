package config

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

func TestPanelPowerPersistsAcrossManagerRestart(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		for _, saveFailure := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/saved", true: "/save_failure"}[saveFailure], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "transports.json")
				spec := transport.TransportSpec{Tag: "proxy", DisplayName: "MyPN #2", Type: "sing-box", Interface: "pbr0",
					Link: "trojan://old@example.invalid:443", AutoStart: !enabled}
				sibling := transport.TransportSpec{Tag: "other", Type: "sing-box", Interface: "pbr1",
					Link: "trojan://other@example.invalid:443", AutoStart: true}
				cfg := Config{APIKey: "secret", SingBoxBinary: "sing-box", RuntimeDir: t.TempDir(),
					Transports: []transport.TransportSpec{spec, sibling}}
				if err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				manager := transport.NewManager()
				supervisor := transport.NewSupervisor(manager)
				for _, item := range cfg.Transports {
					if err := manager.Add(&desiredStateTransport{tag: item.Tag}); err != nil {
						t.Fatal(err)
					}
					supervisor.RegisterWithDesired(item, false)
				}
				admin := NewAdmin(path, cfg, manager, supervisor)
				revision := admin.Revision()
				if saveFailure {
					failNextDesiredStateSave(t)
				}
				err := admin.SetEnabled(context.Background(), spec.Tag, enabled)
				if (err != nil) != saveFailure {
					t.Fatalf("saveFailure=%v error=%v", saveFailure, err)
				}
				expectedSpec, expectedDesired := spec, false
				if !saveFailure {
					expectedSpec.AutoStart, expectedDesired = enabled, enabled
				}
				status, err := supervisor.Status(context.Background(), spec.Tag)
				if err != nil || status.DesiredUp != expectedDesired {
					t.Fatalf("runtime intent=%v expected=%v error=%v", status.DesiredUp, expectedDesired, err)
				}
				status, err = supervisor.Status(context.Background(), sibling.Tag)
				if err != nil || status.DesiredUp {
					t.Fatalf("power switch changed manually stopped sibling: %#v error=%v", status, err)
				}
				stored, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if stored.APIKey != cfg.APIKey || !reflect.DeepEqual(stored.Transports, []transport.TransportSpec{expectedSpec, sibling}) {
					t.Fatal("saved power switch changed other connection fields")
				}
				if saveFailure && admin.Revision() != revision {
					t.Fatal("failed power switch changed configuration revision")
				}
				// A fresh manager must derive the exact same boot intent from disk.
				freshManager := transport.NewManager()
				freshSupervisor := transport.NewSupervisor(freshManager)
				for _, item := range stored.Transports {
					if err := freshManager.Add(&desiredStateTransport{tag: item.Tag}); err != nil {
						t.Fatal(err)
					}
					freshSupervisor.Register(item)
				}
				status, err = freshSupervisor.Status(context.Background(), spec.Tag)
				if err != nil || status.DesiredUp != expectedSpec.AutoStart {
					t.Fatalf("reboot intent=%v expected=%v error=%v", status.DesiredUp, expectedSpec.AutoStart, err)
				}
			})
		}
	}
}

func TestPanelPowerAlsoAppliesAnUnchangedBootPreference(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "transports.json")
		spec := transport.TransportSpec{Tag: "proxy", Type: "sing-box", AutoStart: enabled}
		cfg := Config{APIKey: "secret", Transports: []transport.TransportSpec{spec}}
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
		manager := transport.NewManager()
		if err := manager.Add(&desiredStateTransport{tag: spec.Tag}); err != nil {
			t.Fatal(err)
		}
		supervisor := transport.NewSupervisor(manager)
		supervisor.RegisterWithDesired(spec, !enabled)
		admin := NewAdmin(path, cfg, manager, supervisor)
		revision := admin.Revision()
		if err := admin.SetEnabled(context.Background(), spec.Tag, enabled); err != nil {
			t.Fatal(err)
		}
		status, err := supervisor.Status(context.Background(), spec.Tag)
		if err != nil || status.DesiredUp != enabled || admin.Revision() != revision {
			t.Fatalf("unchanged preference did not apply runtime intent: %#v error=%v", status, err)
		}
	}
}

func TestPanelPowerSharedOffSurvivesOrdinaryBoot(t *testing.T) {
	for _, saveFailure := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "transports.json")
		// Turning an already stopped member off must not require sing-box at all.
		binary := filepath.Join(t.TempDir(), "missing-sing-box")
		spec := transport.TransportSpec{Tag: "proxy", DisplayName: "MyPN #2", Type: "sing-box", Interface: "pbr0",
			Link: "trojan://old@example.invalid:443", AutoStart: true}
		sibling := transport.TransportSpec{Tag: "other", Type: "sing-box", Interface: "pbr1",
			Link: "trojan://other@example.invalid:443", AutoStart: true}
		cfg := Config{APIKey: "secret", SingBoxBinary: binary, SingBoxProcessMode: SingBoxProcessModeShared,
			RuntimeDir: t.TempDir(), Transports: []transport.TransportSpec{spec, sibling}}
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
		group, err := transport.NewSharedSingBoxGroupWithDesired(cfg.Transports, binary, cfg.RuntimeDir,
			cfg.HealthEndpoint(), map[string]bool{spec.Tag: false, sibling.Tag: false})
		if err != nil {
			t.Fatal(err)
		}
		manager := transport.NewManager()
		if err := manager.SetSharedGroup(group); err != nil {
			t.Fatal(err)
		}
		supervisor := transport.NewSupervisor(manager)
		for _, item := range cfg.Transports {
			member, err := group.Member(item.Tag)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Add(member); err != nil {
				t.Fatal(err)
			}
			supervisor.Register(item)
		}
		admin := NewAdmin(path, cfg, manager, supervisor)
		if saveFailure {
			failNextDesiredStateSave(t)
		}
		err = admin.SetEnabled(context.Background(), spec.Tag, false)
		if (err != nil) != saveFailure {
			t.Fatalf("shared saveFailure=%v error=%v", saveFailure, err)
		}
		for _, tag := range []string{spec.Tag, sibling.Tag} {
			status, err := supervisor.Status(context.Background(), tag)
			if err != nil || status.DesiredUp {
				t.Fatalf("power switch revived shared member %s: %#v error=%v", tag, status, err)
			}
		}
		stored, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := transport.NewSharedSingBoxGroup(stored.Transports, binary, t.TempDir(), stored.HealthEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range stored.Transports {
			member, err := fresh.Member(item.Tag)
			if err != nil {
				t.Fatal(err)
			}
			if got := member.Status(context.Background()).DesiredUp; got != (item.Tag == sibling.Tag || saveFailure) {
				t.Fatalf("ordinary boot restored wrong shared intent for %s: %v", item.Tag, got)
			}
		}
		if !saveFailure {
			revision := admin.Revision()
			if err := admin.SetEnabled(context.Background(), spec.Tag, true); err == nil {
				t.Fatal("missing binary unexpectedly started")
			}
			status, err := supervisor.Status(context.Background(), spec.Tag)
			if err != nil || status.DesiredUp || admin.Revision() != revision {
				t.Fatalf("failed shared start changed saved/runtime intent: %#v error=%v", status, err)
			}
		}
	}
}

func TestPanelPowerDoesNotControlNativeOrMissingInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{APIKey: "secret", Transports: []transport.TransportSpec{{Tag: "native", Type: "native", AutoStart: true}}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	admin := NewAdmin(path, cfg, manager, transport.NewSupervisor(manager))
	revision := admin.Revision()
	for _, tag := range []string{"native", "missing"} {
		if err := admin.SetEnabled(context.Background(), tag, false); err == nil {
			t.Fatalf("unexpected power operation accepted for %s", tag)
		}
	}
	if admin.Revision() != revision {
		t.Fatal("invalid operation changed configuration revision")
	}
}
