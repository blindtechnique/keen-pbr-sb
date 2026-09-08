package config

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

func TestAdminPersistsCollidingGeneratedTunAddresses(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "sequential"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "transports.json")
			cfg := Config{APIKey: "secret", SingBoxBinary: "sing-box", RuntimeDir: t.TempDir()}
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			manager := transport.NewManager()
			admin := NewAdmin(path, cfg, manager, transport.NewSupervisor(manager))
			specs := []transport.TransportSpec{
				{Tag: "node_1", Type: "sing-box", Interface: "vless1", OutboundJSON: `{"type":"direct"}`},
				{Tag: "node_171", Type: "sing-box", Interface: "vless2", OutboundJSON: `{"type":"direct"}`},
			}
			revision := admin.Revision()
			_, matched, valid := admin.ValidateCreateItemsAtRevision(specs, revision)
			if !matched || len(valid) != 2 || !valid[0] || !valid[1] {
				t.Fatal("individual validation rejected normal subscriptions")
			}
			if _, matched, err := admin.ValidateCreateManyAtRevision(specs, revision); err != nil || !matched {
				t.Fatalf("cumulative validation failed: %v", err)
			}
			if len(admin.Specs()) != 0 {
				t.Fatal("validation mutated config")
			}
			if batch {
				if _, matched, err := admin.CreateManyIfRevision(context.Background(), specs, revision); err != nil || !matched {
					t.Fatalf("batch create failed: %v", err)
				}
			} else {
				for _, spec := range specs {
					if err := admin.Create(context.Background(), spec); err != nil {
						t.Fatal(err)
					}
				}
			}
			stored, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(stored.Transports) != 2 || stored.Transports[0].TunAddress != "172.19.57.149/30" || stored.Transports[1].TunAddress != "172.19.57.153/30" {
				t.Fatalf("incorrect persistent allocations: %#v", stored.Transports)
			}
			if err := transport.ValidateUniqueTunAddresses(stored.Transports); err != nil {
				t.Fatal(err)
			}
			// Older callers may omit the field while editing only presentation.
			specs[1].DisplayName = "Edited name"
			if err := admin.Update(context.Background(), specs[1].Tag, specs[1]); err != nil {
				t.Fatal(err)
			}
			if err := admin.Delete(context.Background(), specs[0].Tag); err != nil {
				t.Fatal(err)
			}
			stored, err = Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(stored.Transports) != 1 || stored.Transports[0].TunAddress != "172.19.57.153/30" {
				t.Fatalf("edit/delete moved existing assignment: %#v", stored.Transports)
			}
		})
	}
}
