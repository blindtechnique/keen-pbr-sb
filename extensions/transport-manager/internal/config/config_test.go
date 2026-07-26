package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
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

func TestAdminAliasUpdateKeepsLiveTransport(t *testing.T) {
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
	spec := transport.TransportSpec{
		Tag:       "native_one",
		Type:      "native",
		Interface: "nwg1",
	}
	if err := admin.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	before, ok := manager.Get(spec.Tag)
	if !ok {
		t.Fatal("created transport is missing from manager")
	}

	spec.DisplayName = "Основной туннель"
	if err := admin.Update(context.Background(), spec.Tag, spec); err != nil {
		t.Fatal(err)
	}
	after, ok := manager.Get(spec.Tag)
	if !ok {
		t.Fatal("updated transport is missing from manager")
	}
	if before != after {
		t.Fatal("presentation-only alias update replaced the live transport")
	}

	stored, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Transports[0].DisplayName != spec.DisplayName {
		t.Fatalf("alias was not persisted: %#v", stored.Transports[0])
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

func TestSaveReportsRenameCommitWhenDirectorySyncFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{APIKey: "secret"}
	operations := defaultSaveOperations
	operations.syncDirectory = func(string) error {
		return errors.New("injected directory sync failure")
	}

	result, err := save(path, cfg, operations)
	if err == nil {
		t.Fatal("expected directory sync failure")
	}
	if !result.visible || result.durable {
		t.Fatalf("unexpected save result: %#v", result)
	}
	var committedError *saveError
	if !errors.As(err, &committedError) {
		t.Fatalf("expected typed post-rename error, got %T: %v", err, err)
	}
	if !committedError.result.visible || committedError.result.durable {
		t.Fatalf("unexpected typed error result: %#v", committedError.result)
	}
	if _, readErr := os.Stat(path); readErr != nil {
		t.Fatalf("renamed config is not visible: %v", readErr)
	}
}

func TestAdminSaveRestoresPreviousConfigAfterDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	previous := Config{
		APIKey:     "secret",
		Transports: []transport.TransportSpec{{Tag: "old", Type: "native", Interface: "nwg1"}},
	}
	if err := Save(path, previous); err != nil {
		t.Fatal(err)
	}
	previousBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	originalOperations := defaultSaveOperations
	t.Cleanup(func() {
		defaultSaveOperations = originalOperations
	})
	syncCalls := 0
	defaultSaveOperations.syncDirectory = func(directory string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected first directory sync failure")
		}
		return originalOperations.syncDirectory(directory)
	}

	next := previous
	next.Transports = []transport.TransportSpec{{
		Tag:       "new",
		Type:      "native",
		Interface: "nwg2",
	}}
	if _, err := saveAdminConfig(path, next); err == nil {
		t.Fatal("expected durability failure")
	}
	if syncCalls != 2 {
		t.Fatalf("expected failed commit plus durable rollback, got %d syncs", syncCalls)
	}

	storedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedBytes) != string(previousBytes) {
		t.Fatal("previous config bytes were not restored exactly")
	}
	stored, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Transports) != 1 || stored.Transports[0].Tag != "old" {
		t.Fatalf("previous config was not restored: %#v", stored.Transports)
	}
}

func TestAdminSaveRemovesNewFileAfterDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	originalOperations := defaultSaveOperations
	t.Cleanup(func() {
		defaultSaveOperations = originalOperations
	})
	syncCalls := 0
	defaultSaveOperations.syncDirectory = func(directory string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected first directory sync failure")
		}
		return originalOperations.syncDirectory(directory)
	}

	if _, err := saveAdminConfig(path, Config{APIKey: "secret"}); err == nil {
		t.Fatal("expected durability failure")
	}
	if syncCalls != 2 {
		t.Fatalf("expected failed commit plus durable removal, got %d syncs", syncCalls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("new config survived failed first commit: %v", err)
	}
}

func TestLoadedAndCommittedRevisionTracksExactVisibleConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{
		APIKey: "secret",
		Transports: []transport.TransportSpec{{
			Tag:       "native_one",
			Type:      "native",
			Interface: "nwg1",
		}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	loaded, revision, err := LoadWithRevision(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if revision != configRevision(raw) {
		t.Fatalf("loaded revision does not match visible bytes: %s", revision)
	}

	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	admin := NewAdminWithRevision(path, loaded, revision, manager, supervisor)
	if admin.Revision() != revision {
		t.Fatal("admin lost startup revision")
	}
	updated := loaded
	updated.Transports[0].DisplayName = "Дом"
	if err := admin.Update(context.Background(), "native_one", updated.Transports[0]); err != nil {
		t.Fatal(err)
	}
	updatedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if admin.Revision() != configRevision(updatedRaw) {
		t.Fatal("admin revision does not match committed config")
	}
	if admin.Revision() == revision {
		t.Fatal("revision did not change after committed update")
	}
}

func TestConditionalCreateAllowsOnlyOneWriterPerRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{
		APIKey:        "secret",
		SingBoxBinary: "/opt/bin/sing-box",
		RuntimeDir:    filepath.Join(t.TempDir(), "runtime"),
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := LoadWithRevision(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	admin := NewAdminWithRevision(path, loaded, revision, manager, supervisor)

	type result struct {
		revision string
		matched  bool
		err      error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	for _, spec := range []transport.TransportSpec{
		{Tag: "native_one", Type: "native", Interface: "nwg1"},
		{Tag: "native_two", Type: "native", Interface: "nwg2"},
	} {
		spec := spec
		go func() {
			ready.Done()
			<-start
			nextRevision, matched, createErr := admin.CreateIfRevision(
				context.Background(),
				spec,
				revision,
			)
			results <- result{revision: nextRevision, matched: matched, err: createErr}
		}()
	}
	ready.Wait()
	close(start)

	matchedCount := 0
	staleCount := 0
	for range 2 {
		outcome := <-results
		if outcome.err != nil {
			t.Fatalf("conditional create failed: %v", outcome.err)
		}
		if outcome.matched {
			matchedCount++
			if outcome.revision == revision {
				t.Fatal("winning writer did not advance revision")
			}
		} else {
			staleCount++
		}
	}
	if matchedCount != 1 || staleCount != 1 {
		t.Fatalf("expected one winner and one stale writer, got matched=%d stale=%d", matchedCount, staleCount)
	}

	stored, storedRevision, err := LoadWithRevision(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Transports) != 1 {
		t.Fatalf("both writers committed: %#v", stored.Transports)
	}
	if storedRevision != admin.Revision() {
		t.Fatalf("durable revision %q differs from admin %q", storedRevision, admin.Revision())
	}
	if _, exists := manager.Get(stored.Transports[0].Tag); !exists {
		t.Fatal("winning transport is not registered in runtime manager")
	}
}

func TestValidateUpdatePreservesSecretsWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := Config{
		APIKey:        "secret",
		SingBoxBinary: "/opt/bin/sing-box",
		RuntimeDir:    filepath.Join(t.TempDir(), "runtime"),
		Transports: []transport.TransportSpec{{
			Tag:          "proxy_one",
			Type:         "sing-box",
			Interface:    "kpbrproxy1",
			OutboundJSON: `{"type":"vless","tag":"proxy_one","server":"example.com","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111"}`,
		}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := LoadWithRevision(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	managed, err := transport.NewFromSpec(
		loaded.Transports[0],
		loaded.SingBoxBinary,
		loaded.RuntimeDir,
		loaded.HealthEndpoint(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(managed); err != nil {
		t.Fatal(err)
	}
	supervisor := transport.NewSupervisor(manager)
	supervisor.Register(loaded.Transports[0])
	admin := NewAdminWithRevision(path, loaded, revision, manager, supervisor)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	redactedUpdate := transport.TransportSpec{
		Tag:         "proxy_one",
		DisplayName: "Рабочий прокси",
		Type:        "sing-box",
		Interface:   "kpbrproxy1",
	}
	gotRevision, matched, err := admin.ValidateUpdateAtRevision(
		"proxy_one",
		redactedUpdate,
		revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !matched || gotRevision != revision {
		t.Fatalf("unexpected validation result matched=%t revision=%q", matched, gotRevision)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("update validation changed durable config")
	}
	if admin.Revision() != revision || admin.Specs()[0].DisplayName != "" {
		t.Fatal("update validation changed in-memory config")
	}
}
