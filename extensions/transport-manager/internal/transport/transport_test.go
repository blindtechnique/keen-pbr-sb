package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeTransport struct {
	tag     string
	upError error
	mu      sync.Mutex
	started bool
}

func (f *fakeTransport) Tag() string { return f.tag }
func (f *fakeTransport) Up(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = f.upError == nil
	return f.upError
}
func (f *fakeTransport) Down(context.Context) error {
	f.mu.Lock()
	f.started = false
	f.mu.Unlock()
	return nil
}
func (f *fakeTransport) Status(context.Context) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := StateDown
	if f.started {
		state = StateUp
	}
	return Status{Tag: f.tag, State: state, UpdatedAt: time.Now().UTC()}
}

func TestManagerRejectsDuplicateTags(t *testing.T) {
	manager := NewManager()
	if err := manager.Add(&fakeTransport{tag: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(&fakeTransport{tag: "one"}); err == nil {
		t.Fatal("expected duplicate tag to be rejected")
	}
}

func TestManagerStartsRequestedTransports(t *testing.T) {
	manager := NewManager()
	first := &fakeTransport{tag: "first"}
	second := &fakeTransport{tag: "second"}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(second); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), []string{"first"}); err != nil {
		t.Fatal(err)
	}
	if status, _ := manager.Status(context.Background(), "first"); status.State != StateUp {
		t.Fatalf("first transport state is %s", status.State)
	}
	if status, _ := manager.Status(context.Background(), "second"); status.State != StateDown {
		t.Fatalf("second transport state is %s", status.State)
	}
}

func TestManagerStartJoinsErrors(t *testing.T) {
	manager := NewManager()
	want := errors.New("start failed")
	if err := manager.Add(&fakeTransport{tag: "broken", upError: want}); err != nil {
		t.Fatal(err)
	}
	err := manager.Start(context.Background(), []string{"broken", "missing"})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected joined start error, got %v", err)
	}
}
