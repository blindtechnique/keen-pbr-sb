package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"api_key":"secret","transports":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:12122" {
		t.Fatalf("unexpected listen address: %s", cfg.Listen)
	}
	if cfg.SingBoxBinary != "/opt/bin/sing-box" {
		t.Fatalf("unexpected sing-box binary: %s", cfg.SingBoxBinary)
	}
	if cfg.RuntimeDir != "/opt/var/run/keen-pbr/transports" {
		t.Fatalf("unexpected runtime directory: %s", cfg.RuntimeDir)
	}
}

func TestAdminPersistsCreateUpdateDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{
		Listen:        "127.0.0.1:12122",
		APIKey:        "secret",
		SingBoxBinary: "/opt/bin/sing-box",
		RuntimeDir:    "/tmp/transports",
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	admin := NewAdmin(path, cfg, manager, supervisor)
	spec := transport.TransportSpec{Tag: "native_one", Type: "native", Interface: "nwg1"}
	if err := admin.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	stored, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Transports) != 1 || stored.Transports[0].Interface != "nwg1" {
		t.Fatalf("unexpected stored transports: %#v", stored.Transports)
	}
	spec.Interface = "nwg2"
	if err := admin.Update(context.Background(), spec.Tag, spec); err != nil {
		t.Fatal(err)
	}
	stored, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Transports[0].Interface != "nwg2" {
		t.Fatalf("update was not persisted: %#v", stored.Transports[0])
	}
	if err := admin.Delete(context.Background(), spec.Tag); err != nil {
		t.Fatal(err)
	}
	stored, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Transports) != 0 {
		t.Fatalf("delete was not persisted: %#v", stored.Transports)
	}
}

func TestLoadRejectsEmptyAPIKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"transports":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected empty api_key to be rejected")
	}
}

func TestAdminRedactsUIConfigButExportsSecrets(t *testing.T) {
	spec := transport.TransportSpec{
		Tag:          "proxy_one",
		Type:         "sing-box",
		Interface:    "proxy1",
		Link:         "vless://secret",
		OutboundJSON: `{"type":"vless","uuid":"secret"}`,
		BootstrapDNS: []string{"1.1.1.1"},
		VLESS:        &transport.VLESSSpec{UUID: "secret-uuid"},
	}
	admin := NewAdmin("unused", Config{Transports: []transport.TransportSpec{spec}}, nil, nil)

	redacted := admin.Specs()
	if redacted[0].Link != "" || redacted[0].OutboundJSON != "" || redacted[0].VLESS.UUID != "" {
		t.Fatalf("regular config response leaked secrets: %#v", redacted[0])
	}

	exported := admin.ExportSpecs()
	if exported[0].Link != spec.Link || exported[0].OutboundJSON != spec.OutboundJSON || exported[0].VLESS.UUID != spec.VLESS.UUID {
		t.Fatalf("export omitted transport secrets: %#v", exported[0])
	}
	exported[0].BootstrapDNS[0] = "9.9.9.9"
	exported[0].VLESS.UUID = "changed"
	secondExport := admin.ExportSpecs()
	if secondExport[0].BootstrapDNS[0] != "1.1.1.1" || secondExport[0].VLESS.UUID != "secret-uuid" {
		t.Fatal("export returned references to live configuration")
	}
}
