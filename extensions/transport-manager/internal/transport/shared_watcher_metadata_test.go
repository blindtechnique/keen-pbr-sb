package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSharedRuntimeMetadataAndIdempotentUpPreserveCrashWatcher(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	group.mu.RLock()
	generation := group.generation
	group.mu.RUnlock()
	for _, name := range []string{"Renamed", "Another name"} {
		specs := group.Inventory()
		specs[0].DisplayName = name
		if err := group.ApplyInventory(context.Background(), specs); err != nil {
			t.Fatal(err)
		}
		if err := group.setDesired(context.Background(), specs[0].Tag, true); err != nil {
			t.Fatal(err)
		}
	}
	if fake.startCount() != 1 {
		t.Fatal("metadata edit restarted shared process")
	}
	group.mu.RLock()
	currentGeneration := group.generation
	group.mu.RUnlock()
	if currentGeneration != generation {
		t.Fatal("metadata edit replaced process watcher generation")
	}
	done := make(chan struct{}, 1)
	fake.mu.Lock()
	fake.onCrashRemove = func() { done <- struct{}{} }
	fake.mu.Unlock()
	fake.process(0).terminate(errors.New("crash after metadata edit"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("crash cleanup did not run after metadata edits")
	}
	if fake.crashRemoveCount() != 1 {
		t.Fatal("crash cleanup must run exactly once")
	}
	status := group.memberStatus(context.Background(), "proxy_a")
	if status.State != StateDegraded || status.Error != "crash after metadata edit" {
		t.Fatalf("missing crash state: %#v", status)
	}
}
