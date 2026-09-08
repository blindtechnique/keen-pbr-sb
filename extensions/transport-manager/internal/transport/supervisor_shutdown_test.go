package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSupervisorQueuedLifecycleHonorsCancellation(t *testing.T) {
	for _, action := range []string{"up", "down", "restart"} {
		t.Run(action, func(t *testing.T) {
			manager := NewManager()
			fake := &supervisorFake{tag: "proxy"}
			if err := manager.Add(fake); err != nil {
				t.Fatal(err)
			}
			supervisor := NewSupervisor(manager)
			supervisor.Register(TransportSpec{Tag: fake.tag, Type: "sing-box", AutoStart: true})
			state := supervisor.stateFor(fake.tag)
			state.opMu.Lock()
			defer state.opMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				switch action {
				case "up":
					done <- supervisor.Up(ctx, fake.tag)
				case "down":
					done <- supervisor.Down(ctx, fake.tag)
				case "restart":
					done <- supervisor.Restart(ctx, fake.tag)
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("action error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("queued action ignored its context")
			}
			if started, calls := fake.snapshot(); started || calls != 0 {
				t.Fatal("canceled queued action started a transport")
			}
			if !state.desired {
				t.Fatal("canceled queued action changed desired state")
			}
		})
	}
}

func TestSupervisorCanceledReconcileReleasesQueuedWork(t *testing.T) {
	manager := NewManager()
	fake := &supervisorFake{tag: "proxy"}
	if err := manager.Add(fake); err != nil {
		t.Fatal(err)
	}
	supervisor := NewSupervisor(manager)
	supervisor.Register(TransportSpec{Tag: fake.tag, Type: "sing-box", AutoStart: true})
	state := supervisor.stateFor(fake.tag)
	state.inFlight = true
	state.opMu.Lock()
	defer state.opMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	supervisor.reconcileOne(ctx, fake.tag, state)
	if state.inFlight {
		t.Fatal("canceled reconcile kept in-flight work set")
	}
	if started, calls := fake.snapshot(); started || calls != 0 {
		t.Fatal("canceled reconcile started a transport")
	}
	supervisor.reconcile(ctx)
	if state.inFlight {
		t.Fatal("stopped supervisor scheduled new work")
	}
}
