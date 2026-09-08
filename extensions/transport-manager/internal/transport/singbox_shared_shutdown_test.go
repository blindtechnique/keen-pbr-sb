package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func sharedShutdownGroup(t *testing.T, hooks sharedRuntimeHooks) *SharedSingBoxGroup {
	t.Helper()
	hooks.startupGrace = 0
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, hooks,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = group.Close(ctx)
	})
	return group
}

func sharedShutdownWait(t *testing.T, label string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func sharedShutdownResult(t *testing.T, label string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
		return nil
	}
}

func sharedShutdownClose(t *testing.T, group *SharedSingBoxGroup) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := group.Close(ctx); err != nil {
		t.Fatalf("Close did not finish the in-flight operation: %v", err)
	}
}

func sharedShutdownNoChildren(t *testing.T, fake *fakeSharedRuntime) {
	t.Helper()
	fake.mu.Lock()
	processes := append([]*fakeSharedProcess(nil), fake.processes...)
	fake.mu.Unlock()
	for _, process := range processes {
		if process.Alive() {
			t.Errorf("owned child %d is still alive after Close", process.PID())
		}
	}
}

func sharedShutdownNextSpecs() []TransportSpec {
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	return next
}

func TestSharedShutdownCancelsCandidateReadinessWithoutStartingRollback(t *testing.T) {
	fake := &fakeSharedRuntime{}
	hooks := fake.hooks()
	interfaceByName := hooks.interfaceByName
	readinessEntered := make(chan struct{})
	var once sync.Once
	hooks.interfaceByName = func(name string) (*net.Interface, error) {
		if fake.startCount() == 2 {
			once.Do(func() { close(readinessEntered) })
		}
		return interfaceByName(name)
	}
	group := sharedShutdownGroup(t, hooks)
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.missingInterface = "vless1"
	fake.mu.Unlock()
	t.Cleanup(func() {
		fake.mu.Lock()
		fake.missingInterface = ""
		fake.mu.Unlock()
	})
	done := make(chan error, 1)
	go func() { done <- group.ApplyInventory(context.Background(), sharedShutdownNextSpecs()) }()
	sharedShutdownWait(t, "candidate readiness", readinessEntered)
	sharedShutdownClose(t, group)
	if err := sharedShutdownResult(t, "cancelled candidate", done); err == nil {
		t.Fatal("candidate readiness unexpectedly succeeded during shutdown")
	}
	if got := fake.startCount(); got != 2 {
		t.Fatalf("shutdown started a rollback or replacement: start count = %d, want 2", got)
	}
	sharedShutdownNoChildren(t, fake)
}

func TestSharedShutdownCancelsBackgroundConfigValidation(t *testing.T) {
	for _, apply := range []bool{false, true} {
		name := "validate"
		if apply {
			name = "apply"
		}
		t.Run(name, func(t *testing.T) {
			fake := &fakeSharedRuntime{}
			hooks := fake.hooks()
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			hooks.checkConfig = func(ctx context.Context, _, _ string) error {
				once.Do(func() { close(entered) })
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					return errors.New("test cleanup released validation")
				}
			}
			group := sharedShutdownGroup(t, hooks)
			t.Cleanup(func() { close(release) })
			done := make(chan error, 1)
			go func() {
				if apply {
					done <- group.ApplyInventory(context.Background(), sharedShutdownNextSpecs())
				} else {
					done <- group.ValidateInventory(context.Background(), sharedShutdownNextSpecs())
				}
			}()
			sharedShutdownWait(t, "config validation", entered)
			sharedShutdownClose(t, group)
			if err := sharedShutdownResult(t, "cancelled validation", done); !errors.Is(err, context.Canceled) {
				t.Fatalf("validation error = %v, want context cancellation", err)
			}
			if got := fake.startCount(); got != 0 {
				t.Fatalf("shutdown during validation spawned %d processes", got)
			}
			sharedShutdownNoChildren(t, fake)
		})
	}
}

func TestSharedShutdownRejectsQueuedAndNewRuntimeOperations(t *testing.T) {
	fake := &fakeSharedRuntime{}
	group := sharedShutdownGroup(t, fake.hooks())
	group.opMu.Lock()
	locked := true
	defer func() {
		if locked {
			group.opMu.Unlock()
		}
	}()
	operations := map[string]func(context.Context) error{
		"restart":   group.Restart,
		"reconcile": group.Reconcile,
	}
	results := make(map[string]<-chan error)
	for name, operation := range operations {
		entered := make(chan struct{})
		done := make(chan error, 1)
		go func(operation func(context.Context) error) {
			close(entered)
			done <- operation(context.Background())
		}(operation)
		sharedShutdownWait(t, "queued "+name, entered)
		results[name] = done
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := group.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close while opMu is held = %v, want deadline exceeded", err)
	}
	group.opMu.Unlock()
	locked = false
	for name, done := range results {
		if err := sharedShutdownResult(t, "queued "+name, done); err == nil {
			t.Errorf("queued %s succeeded after shutdown began", name)
		}
	}
	sharedShutdownClose(t, group)
	for name, operation := range operations {
		if err := operation(context.Background()); err == nil {
			t.Errorf("new %s succeeded after Close", name)
		}
	}
	if got := fake.startCount(); got != 0 {
		t.Fatalf("queued or new operation started %d children after shutdown", got)
	}
	sharedShutdownNoChildren(t, fake)
}

type sharedShutdownSignalProcess struct {
	sharedProcess
	afterSignal func()
}

func (process *sharedShutdownSignalProcess) Stop(ctx context.Context) error {
	err := process.sharedProcess.Stop(ctx)
	process.afterSignal()
	return err
}

func TestSharedShutdownRequestCancellationStillCompletesTransition(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "candidate"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			candidateErr := errors.New("candidate failed to start")
			fake := &fakeSharedRuntime{}
			if rollback {
				fake.failStartAt = map[int]error{2: candidateErr}
			}
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			hooks := fake.hooks()
			startProcess := hooks.startProcess
			hooks.startProcess = func(binary, configPath, logPath string) (sharedProcess, error) {
				process, err := startProcess(binary, configPath, logPath)
				if err == nil && fake.startCount() == 1 {
					return &sharedShutdownSignalProcess{process, cancelRequest}, nil
				}
				return process, err
			}
			ensureRules := hooks.ensureRules
			transitionCtxErr := make(chan error, 1)
			hooks.ensureRules = func(ctx context.Context, specs []TransportSpec) error {
				if fake.startCount() >= 2 {
					transitionCtxErr <- ctx.Err()
				}
				return ensureRules(ctx, specs)
			}
			group := sharedShutdownGroup(t, hooks)
			if err := group.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			next := sharedShutdownNextSpecs()
			err := group.ApplyInventory(requestCtx, next)
			if rollback {
				if !errors.Is(err, candidateErr) {
					t.Fatalf("rollback error = %v, want candidate failure", err)
				}
				next = sharedRuntimeSpecs()
			} else if err != nil {
				t.Fatalf("request cancellation abandoned candidate: %v", err)
			}
			if requestCtx.Err() != context.Canceled {
				t.Fatal("test did not cancel the request after signalling the old process")
			}
			if err := sharedShutdownResult(t, "transition forwarding context", transitionCtxErr); err != nil {
				t.Fatalf("transition inherited cancelled HTTP request: %v", err)
			}
			wantStarts := 2
			if rollback {
				wantStarts = 3
			}
			if got := fake.startCount(); got != wantStarts {
				t.Fatalf("start count = %d, want %d", got, wantStarts)
			}
			if status := group.memberStatus(context.Background(), "proxy_a"); status.State != StateUp || status.PID != 1000+wantStarts {
				t.Fatalf("completed %s is not healthy: %#v", name, status)
			}
			if got := group.Inventory()[0].OutboundJSON; got != next[0].OutboundJSON {
				t.Fatalf("%s did not publish the correct inventory", name)
			}
			sharedShutdownClose(t, group)
			sharedShutdownNoChildren(t, fake)
		})
	}
}

func TestSharedShutdownCancelsAlreadyStartedRollback(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: map[int]error{2: errors.New("candidate start failed")}}
	hooks := fake.hooks()
	ensureRules := hooks.ensureRules
	rollbackEntered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hooks.ensureRules = func(ctx context.Context, specs []TransportSpec) error {
		if fake.startCount() == 3 {
			once.Do(func() { close(rollbackEntered) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return errors.New("test cleanup released rollback")
			}
		}
		return ensureRules(ctx, specs)
	}
	group := sharedShutdownGroup(t, hooks)
	t.Cleanup(func() { close(release) })
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- group.ApplyInventory(context.Background(), sharedShutdownNextSpecs()) }()
	sharedShutdownWait(t, "rollback forwarding", rollbackEntered)
	if !fake.process(1).Alive() {
		t.Fatal("test did not reach a live rollback process")
	}
	sharedShutdownClose(t, group)
	if err := sharedShutdownResult(t, "cancelled rollback", done); !errors.Is(err, context.Canceled) {
		t.Fatalf("rollback error = %v, want shutdown cancellation", err)
	}
	if got := fake.startCount(); got != 3 {
		t.Fatalf("shutdown launched another child after rollback: start count = %d", got)
	}
	sharedShutdownNoChildren(t, fake)
}

func TestSharedShutdownCleansBothInterfacesWhenCancelledApplyReusesTag(t *testing.T) {
	fake := &fakeSharedRuntime{}
	hooks := fake.hooks()
	ensureRules := hooks.ensureRules
	ensureEntered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hooks.ensureRules = func(ctx context.Context, specs []TransportSpec) error {
		if fake.startCount() == 2 {
			once.Do(func() { close(ensureEntered) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return errors.New("test cleanup released candidate rules")
			}
		}
		return ensureRules(ctx, specs)
	}
	var removalMu sync.Mutex
	var removals []map[string]bool
	hooks.removeRules = func(ctx context.Context, tags map[string]bool, specs map[string]TransportSpec) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		interfaces := make(map[string]bool)
		for tag := range tags {
			if spec, present := specs[tag]; present {
				interfaces[spec.Interface] = true
			}
		}
		removalMu.Lock()
		removals = append(removals, interfaces)
		removalMu.Unlock()
		return nil
	}
	group := sharedShutdownGroup(t, hooks)
	t.Cleanup(func() { close(release) })
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].Interface = "vless3"
	done := make(chan error, 1)
	go func() { done <- group.ApplyInventory(context.Background(), next) }()
	sharedShutdownWait(t, "replacement interface forwarding", ensureEntered)
	sharedShutdownClose(t, group)
	if err := sharedShutdownResult(t, "cancelled interface replacement", done); !errors.Is(err, context.Canceled) {
		t.Fatalf("apply error = %v, want shutdown cancellation", err)
	}
	removalMu.Lock()
	var closedInterfaces map[string]bool
	if len(removals) != 0 {
		closedInterfaces = removals[len(removals)-1]
	}
	removalMu.Unlock()
	for _, iface := range []string{"vless1", "vless2", "vless3"} {
		if !closedInterfaces[iface] {
			t.Errorf("Close lost cleanup target %q after same-tag replacement: %v", iface, closedInterfaces)
		}
	}
	if got := fake.startCount(); got != 2 {
		t.Fatalf("cancelled interface replacement spawned a late child: %d starts", got)
	}
	sharedShutdownNoChildren(t, fake)
}

type sharedShutdownPendingStopProcess struct {
	sharedProcess
	mu          sync.Mutex
	stopCalls   int
	firstCtxErr chan error
}

func (process *sharedShutdownPendingStopProcess) Stop(ctx context.Context) error {
	process.mu.Lock()
	process.stopCalls++
	call := process.stopCalls
	process.mu.Unlock()
	if call == 1 {
		// Model the interval after a cancelled Stop signals kill but before the
		// child is reaped. The group must retain this exact live process.
		process.firstCtxErr <- ctx.Err()
		return ctx.Err()
	}
	return process.sharedProcess.Stop(ctx)
}

func TestSharedShutdownRetainsCandidateUntilPendingStopCompletes(t *testing.T) {
	fake := &fakeSharedRuntime{}
	hooks := fake.hooks()
	startProcess := hooks.startProcess
	startedCandidate := make(chan *sharedShutdownPendingStopProcess, 1)
	hooks.startProcess = func(binary, configPath, logPath string) (sharedProcess, error) {
		process, err := startProcess(binary, configPath, logPath)
		if err == nil && fake.startCount() == 2 {
			candidate := &sharedShutdownPendingStopProcess{
				sharedProcess: process,
				firstCtxErr:   make(chan error, 1),
			}
			startedCandidate <- candidate
			return candidate, nil
		}
		return process, err
	}
	ensureRules := hooks.ensureRules
	ensureEntered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hooks.ensureRules = func(ctx context.Context, specs []TransportSpec) error {
		if fake.startCount() == 2 {
			once.Do(func() { close(ensureEntered) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return errors.New("test cleanup released candidate rules")
			}
		}
		return ensureRules(ctx, specs)
	}
	group := sharedShutdownGroup(t, hooks)
	t.Cleanup(func() { close(release) })
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- group.ApplyInventory(context.Background(), sharedShutdownNextSpecs()) }()
	sharedShutdownWait(t, "candidate forwarding before pending stop", ensureEntered)
	var candidate *sharedShutdownPendingStopProcess
	select {
	case candidate = <-startedCandidate:
	default:
		t.Fatal("candidate forwarding began without publishing its exact process")
	}
	sharedShutdownClose(t, group)
	if err := sharedShutdownResult(t, "cancelled candidate apply", done); !errors.Is(err, context.Canceled) {
		t.Fatalf("apply error = %v, want shutdown cancellation", err)
	}
	if err := sharedShutdownResult(t, "first candidate stop", candidate.firstCtxErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Stop context = %v, want cancelled transition", err)
	}
	candidate.mu.Lock()
	stopCalls := candidate.stopCalls
	candidate.mu.Unlock()
	if stopCalls != 2 {
		t.Fatalf("exact candidate Stop called %d times, want cancelled stop then Close retry", stopCalls)
	}
	if got := fake.startCount(); got != 2 {
		t.Fatalf("pending stop caused an unwanted rollback or replacement: %d starts", got)
	}
	sharedShutdownNoChildren(t, fake)
}
