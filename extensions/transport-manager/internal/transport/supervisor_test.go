package transport

import (
	"context"
	"sync"
	"testing"
	"time"
)

type supervisorFake struct {
	tag       string
	mu        sync.Mutex
	started   bool
	upCalls   int
	failCalls int
}

func (f *supervisorFake) Tag() string { return f.tag }

func (f *supervisorFake) Up(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upCalls++
	if f.upCalls <= f.failCalls {
		return context.DeadlineExceeded
	}
	f.started = true
	return nil
}

func (f *supervisorFake) Down(context.Context) error {
	f.mu.Lock()
	f.started = false
	f.mu.Unlock()
	return nil
}

func (f *supervisorFake) Status(context.Context) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := StateDown
	if f.started {
		state = StateUp
	}
	return Status{
		Tag: f.tag, Type: "sing-box-vless-reality", Interface: "pbr0",
		State: state, UpdatedAt: time.Now().UTC(),
	}
}

func (f *supervisorFake) snapshot() (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started, f.upCalls
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestSupervisorRetriesManagedTransport(t *testing.T) {
	manager := NewManager()
	fake := &supervisorFake{tag: "reality", failCalls: 2}
	if err := manager.Add(fake); err != nil {
		t.Fatal(err)
	}
	supervisor := newSupervisor(manager, time.Millisecond, 2*time.Millisecond, 4*time.Millisecond)
	supervisor.stablePeriod = 2 * time.Millisecond
	supervisor.Register(TransportSpec{Tag: fake.tag, Type: "sing-box-vless-reality", AutoStart: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go supervisor.Run(ctx)

	waitFor(t, func() bool {
		started, calls := fake.snapshot()
		return started && calls == 3
	})
	var status Status
	waitFor(t, func() bool {
		status, _ = supervisor.Status(context.Background(), fake.tag)
		return status.RetryCount == 0
	})
	status, err := supervisor.Status(context.Background(), fake.tag)
	if err != nil {
		t.Fatal(err)
	}
	if !status.DesiredUp || status.RetryCount != 0 || status.NextRetryAt != nil {
		t.Fatalf("unexpected recovered status: %#v", status)
	}
}

func TestSupervisorBacksOffAfterUnstableCrash(t *testing.T) {
	manager := NewManager()
	fake := &supervisorFake{tag: "flapping"}
	if err := manager.Add(fake); err != nil {
		t.Fatal(err)
	}
	supervisor := newSupervisor(manager, time.Millisecond, 20*time.Millisecond, 20*time.Millisecond)
	supervisor.Register(TransportSpec{Tag: fake.tag, Type: "sing-box-vless-reality", AutoStart: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go supervisor.Run(ctx)
	waitFor(t, func() bool {
		started, _ := fake.snapshot()
		return started
	})
	if err := fake.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		status, _ := supervisor.Status(context.Background(), fake.tag)
		return status.RetryCount == 1 && status.NextRetryAt != nil
	})
	_, calls := fake.snapshot()
	if calls != 1 {
		t.Fatalf("transport restarted without backoff: calls=%d", calls)
	}
}

func TestSupervisorManualDownSuppressesRestart(t *testing.T) {
	manager := NewManager()
	fake := &supervisorFake{tag: "reality"}
	if err := manager.Add(fake); err != nil {
		t.Fatal(err)
	}
	supervisor := newSupervisor(manager, time.Millisecond, time.Millisecond, 2*time.Millisecond)
	supervisor.Register(TransportSpec{Tag: fake.tag, Type: "sing-box-vless-reality", AutoStart: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go supervisor.Run(ctx)
	waitFor(t, func() bool {
		started, _ := fake.snapshot()
		return started
	})

	if err := supervisor.Down(context.Background(), fake.tag); err != nil {
		t.Fatal(err)
	}
	_, callsBefore := fake.snapshot()
	time.Sleep(10 * time.Millisecond)
	started, callsAfter := fake.snapshot()
	if started || callsAfter != callsBefore {
		t.Fatalf("manual stop was not respected: started=%v calls=%d->%d", started, callsBefore, callsAfter)
	}
	status, err := supervisor.Status(context.Background(), fake.tag)
	if err != nil {
		t.Fatal(err)
	}
	if status.DesiredUp {
		t.Fatal("manual stop must clear desired_up")
	}
}

func TestSupervisorDoesNotRegisterNativeTransport(t *testing.T) {
	manager := NewManager()
	supervisor := newSupervisor(manager, time.Millisecond, time.Millisecond, time.Millisecond)
	supervisor.Register(TransportSpec{Tag: "native", Type: "native", AutoStart: true})
	if len(supervisor.states) != 0 {
		t.Fatal("native transport must not be supervised")
	}
}
