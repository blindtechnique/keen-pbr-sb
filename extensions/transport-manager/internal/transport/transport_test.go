package transport

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty stays optional"},
		{name: "unicode alias", value: "Основной туннель"},
		{name: "eighty code points", value: strings.Repeat("я", 80)},
		{name: "eighty supplementary code points", value: strings.Repeat("🚀", 80)},
		{name: "emoji joiner sequence", value: "Семья 👨‍👩‍👦"},
		{name: "ascii whitespace", value: " \t\n", wantErr: true},
		{name: "unicode whitespace", value: "\u00a0\u3000", wantErr: true},
		{name: "control", value: "VPN\u0000", wantErr: true},
		{name: "C1 control", value: "VPN\u0085", wantErr: true},
		{name: "bidirectional override", value: "safe\u202etxt.exe", wantErr: true},
		{name: "bidirectional isolate", value: "safe\u2066name", wantErr: true},
		{name: "invalid UTF-8", value: string([]byte{0xff, 'a'}), wantErr: true},
		{name: "eighty one code points", value: strings.Repeat("я", 81), wantErr: true},
		{name: "eighty one supplementary code points", value: strings.Repeat("🚀", 81), wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDisplayName(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateDisplayName(%q) error = %v, wantErr = %v", test.value, err, test.wantErr)
			}
		})
	}
}

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
