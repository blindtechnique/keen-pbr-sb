package transport

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type blockingExitCleanupRunner struct {
	*fakeFirewallRunner
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (runner *blockingExitCleanupRunner) Run(ctx context.Context, binary string, args []string) firewallCommandResult {
	for _, arg := range args {
		if arg == "-D" {
			runner.once.Do(func() { close(runner.entered); <-runner.release })
			break
		}
	}
	return runner.fakeFirewallRunner.Run(ctx, binary, args)
}

func TestSingBoxRestartWaitsForOldForwardingCleanupAfterKill(t *testing.T) {
	runner := &blockingExitCleanupRunner{fakeFirewallRunner: newFakeFirewallRunner(), entered: make(chan struct{}), release: make(chan struct{})}
	s, listener := isolatedShutdownFixture(t, runner)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(release)
	upDone := make(chan error, 1)
	go func() { upDone <- s.Up(context.Background()) }()
	oldConnection := acceptShutdownChild(t, listener)
	if err := sharedShutdownResult(t, "initial Up", upDone); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldCmd := s.cmd
	s.mu.Unlock()
	manager := NewManager()
	if err := manager.Add(s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	restartDone := make(chan error, 1)
	go func() { restartDone <- manager.Restart(ctx, s.Tag()) }()
	sharedShutdownWait(t, "old forwarding cleanup", runner.entered)
	requireChildStopped(t, oldConnection)
	// Cross the real five-second Signal/Kill boundary and a further two
	// seconds while cleanup owns the old rules. The existing operation budget
	// must allow normal xtables contention, not return success or a new timeout.
	select {
	case err := <-restartDone:
		t.Fatalf("Restart returned before old cleanup completed: %v", err)
	case <-time.After(7100 * time.Millisecond):
	}
	release()
	newConnection := acceptShutdownChild(t, listener)
	if err := sharedShutdownResult(t, "replacement startup", restartDone); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	newCmd, state := s.cmd, s.state
	s.mu.Unlock()
	if newCmd == nil || newCmd == oldCmd || state != StateUp {
		t.Fatalf("Restart did not install a new live process: same cmd=%v state=%s", newCmd == oldCmd, state)
	}
	if !systemForwardingRules.rulesPresent("testtun") {
		t.Fatal("old exit cleanup removed the replacement's forwarding rules")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := s.Down(stopCtx); err != nil {
		t.Fatal(err)
	}
	requireChildStopped(t, newConnection)
}

func TestSingBoxUpDoesNotAcceptExitedCommandWhileCleanupIsPending(t *testing.T) {
	runner := &blockingExitCleanupRunner{fakeFirewallRunner: newFakeFirewallRunner(), entered: make(chan struct{}), release: make(chan struct{})}
	s, listener := isolatedShutdownFixture(t, runner)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(release)
	upDone := make(chan error, 1)
	go func() { upDone <- s.Up(context.Background()) }()
	oldConnection := acceptShutdownChild(t, listener)
	if err := sharedShutdownResult(t, "initial Up", upDone); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldCmd, oldDone := s.cmd, s.done
	s.mu.Unlock()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopCancel()
	stopDone := make(chan error, 1)
	go func() { stopDone <- s.Down(stopCtx) }()
	sharedShutdownWait(t, "old forwarding cleanup", runner.entered)
	if err := sharedShutdownResult(t, "bounded Down", stopDone); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Down error = %v, want deadline exceeded", err)
	}
	requireChildStopped(t, oldConnection)
	startCtx, startCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer startCancel()
	if err := s.Up(startCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Up accepted an exited process with pending cleanup: %v", err)
	}
	s.mu.Lock()
	retainedCmd := s.cmd
	s.mu.Unlock()
	if retainedCmd != oldCmd {
		t.Fatal("timed-out Up discarded ownership of the old cleanup")
	}
	release()
	select {
	case <-oldDone:
	case <-time.After(2 * time.Second):
		t.Fatal("old exit did not complete after releasing cleanup")
	}
	go func() { upDone <- s.Up(context.Background()) }()
	newConnection := acceptShutdownChild(t, listener)
	if err := sharedShutdownResult(t, "Up after cleanup", upDone); err != nil {
		t.Fatal(err)
	}
	if !systemForwardingRules.rulesPresent("testtun") {
		t.Fatal("new process did not retain its forwarding rules")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := s.Down(closeCtx); err != nil {
		t.Fatal(err)
	}
	requireChildStopped(t, newConnection)
}

func TestSingBoxCancelledDownMarksPendingExitBeforeWait(t *testing.T) {
	s, listener := isolatedShutdownFixture(t, newFakeFirewallRunner())
	logFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(s.binary, "run")
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	before := time.Now().Add(-time.Second)
	s.mu.Lock()
	s.cmd, s.done, s.state, s.updated = cmd, done, StateUp, before
	s.mu.Unlock()
	// Hold only the scheduling of the normal wait goroutine, not a production
	// mutex. This exposes the short interval between Kill and wait's state update.
	var waitOnce sync.Once
	startWait := func() { waitOnce.Do(func() { go s.wait(cmd, logFile) }) }
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		startWait()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("owned child was not reaped")
		}
	})
	connection := acceptShutdownChild(t, listener)
	stopCtx, stopCancel := context.WithCancel(context.Background())
	stopCancel()
	if err := s.Down(stopCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired Down error = %v, want context cancelled", err)
	}
	s.mu.Lock()
	state, retained, updated := s.state, s.cmd, s.updated
	s.mu.Unlock()
	if state != StateDown || retained != cmd || !updated.After(before) {
		t.Fatalf("cancelled Down lost stopping state/ownership before wait: state=%s retained=%v updated=%v", state, retained == cmd, updated)
	}
	requireChildStopped(t, connection)
	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer startCancel()
	if err := s.Up(startCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Up accepted a killed child before wait was scheduled: %v", err)
	}
	startWait()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not complete exit and cleanup")
	}
	s.mu.Lock()
	retained = s.cmd
	s.mu.Unlock()
	if retained != nil {
		t.Fatal("completed cleanup retained the old command")
	}
}
