package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeSharedProcess struct {
	mu        sync.Mutex
	pid       int
	alive     bool
	done      chan struct{}
	err       error
	stopCalls int
	stopErr   error
	keepAlive bool
}

func newFakeSharedProcess(pid int) *fakeSharedProcess {
	return &fakeSharedProcess{pid: pid, alive: true, done: make(chan struct{})}
}

func (p *fakeSharedProcess) PID() int { return p.pid }
func (p *fakeSharedProcess) Alive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.alive
}
func (p *fakeSharedProcess) Done() <-chan struct{} { return p.done }
func (p *fakeSharedProcess) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
func (p *fakeSharedProcess) Stop(context.Context) error {
	p.mu.Lock()
	p.stopCalls++
	err, keepAlive := p.stopErr, p.keepAlive
	p.mu.Unlock()
	if err != nil && keepAlive {
		return err
	}
	p.terminate(nil)
	return err
}

func (p *fakeSharedProcess) terminate(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.alive {
		p.alive = false
		p.err = err
		close(p.done)
	}
}

type fakeSharedRuntime struct {
	mu               sync.Mutex
	startCalls       int
	checkCalls       int
	ensureCalls      int
	removeCalls      int
	crashRemoveCalls int
	failStartAt      map[int]error
	failEnsureAt     map[int]error
	crashAt          map[int]time.Duration
	blockStartAt     map[int]<-chan struct{}
	processes        []*fakeSharedProcess
	check            func([]byte) error
	now              func() time.Time
	onCrashRemove    func()
	rulesMissing     bool
	missingInterface string
}

func (f *fakeSharedRuntime) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls
}

func (f *fakeSharedRuntime) process(index int) *fakeSharedProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.processes[index]
}

func (f *fakeSharedRuntime) crashRemoveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.crashRemoveCalls
}

func (f *fakeSharedRuntime) ensureCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensureCalls
}

func (f *fakeSharedRuntime) hooks() sharedRuntimeHooks {
	return sharedRuntimeHooks{
		checkConfig: func(_ context.Context, _, path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f.mu.Lock()
			f.checkCalls++
			check := f.check
			f.mu.Unlock()
			if check != nil {
				return check(data)
			}
			return nil
		},
		startProcess: func(_, _, _ string) (sharedProcess, error) {
			f.mu.Lock()
			f.startCalls++
			call := f.startCalls
			startErr := f.failStartAt[call]
			block := f.blockStartAt[call]
			crashAfter, shouldCrash := f.crashAt[call]
			f.mu.Unlock()
			if startErr != nil {
				return nil, startErr
			}
			if block != nil {
				<-block
			}
			process := newFakeSharedProcess(1000 + call)
			f.mu.Lock()
			f.processes = append(f.processes, process)
			f.mu.Unlock()
			if shouldCrash {
				go func() {
					time.Sleep(crashAfter)
					process.terminate(errors.New("candidate crashed during startup"))
				}()
			}
			return process, nil
		},
		interfaceByName: func(name string) (*net.Interface, error) {
			f.mu.Lock()
			missing := f.missingInterface
			f.mu.Unlock()
			if name == missing {
				return nil, errors.New("interface missing")
			}
			return &net.Interface{Name: name}, nil
		},
		ensureRules: func([]TransportSpec) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.ensureCalls++
			return f.failEnsureAt[f.ensureCalls]
		},
		rulesPresent: func([]TransportSpec) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return !f.rulesMissing
		},
		removeRules: func(map[string]bool, map[string]TransportSpec) {
			f.mu.Lock()
			f.removeCalls++
			f.mu.Unlock()
		},
		removeCrashRules: func(map[string]bool, map[string]TransportSpec) {
			f.mu.Lock()
			f.crashRemoveCalls++
			callback := f.onCrashRemove
			f.mu.Unlock()
			if callback != nil {
				callback()
			}
		},
		now: func() time.Time {
			f.mu.Lock()
			now := f.now
			f.mu.Unlock()
			if now != nil {
				return now()
			}
			return time.Now().UTC()
		},
	}
}

func sharedRuntimeSpecs() []TransportSpec {
	first := sharedConfigSpec("proxy_a", "vless1", "a.example")
	first.AutoStart = true
	second := sharedConfigSpec("proxy_b", "vless2", "b.example")
	second.AutoStart = true
	return []TransportSpec{first, second}
}

func TestSharedRuntimeStartsAllDesiredMembersInOneProcess(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := group.memberStatus(context.Background(), "proxy_a")
	second := group.memberStatus(context.Background(), "proxy_b")
	if first.State != StateUp || second.State != StateUp {
		t.Fatalf("members are not up: %#v / %#v", first, second)
	}
	if first.PID == 0 || first.PID != second.PID {
		t.Fatalf("logical members do not share one PID: %d / %d", first.PID, second.PID)
	}
	if fake.startCount() != 1 {
		t.Fatalf("expected one process start, got %d", fake.startCount())
	}
}

func TestSharedRuntimeReadinessChecksProcessInterfaceAndRules(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if group.localRuntimeReady("proxy_a") {
		t.Fatal("stopped shared runtime was reported ready")
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !group.localRuntimeReady("proxy_a") {
		t.Fatal("running shared runtime was not reported ready")
	}
	fake.mu.Lock()
	fake.missingInterface = "vless1"
	fake.mu.Unlock()
	if group.localRuntimeReady("proxy_a") {
		t.Fatal("missing TUN interface was reported ready")
	}
	fake.mu.Lock()
	fake.missingInterface = ""
	fake.rulesMissing = true
	fake.mu.Unlock()
	if group.localRuntimeReady("proxy_a") {
		t.Fatal("missing forwarding rules were reported ready")
	}
}

func TestSharedRuntimeCapsSharedLogDuringReconciliation(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	runtimeDir := t.TempDir()
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", runtimeDir, RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer group.Close(context.Background())

	logPath := filepath.Join(runtimeDir, "shared.log")
	if err := os.WriteFile(logPath, make([]byte, 2*1024*1024+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := group.EnsureRuntimeRules(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected oversized shared log to be truncated, got %d bytes", info.Size())
	}
}

func TestSharedRuntimeTracksUpdatedAtPerMember(t *testing.T) {
	var clockMu sync.Mutex
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	fake.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		current = current.Add(time.Second)
		return current
	}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstBefore := group.memberStatus(context.Background(), "proxy_a").UpdatedAt
	secondBefore := group.memberStatus(context.Background(), "proxy_b").UpdatedAt

	next := sharedRuntimeSpecs()
	next[0].DisplayName = "Only proxy A changed"
	if err := group.ApplyInventory(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	firstAfter := group.memberStatus(context.Background(), "proxy_a").UpdatedAt
	secondAfter := group.memberStatus(context.Background(), "proxy_b").UpdatedAt
	if !firstAfter.After(firstBefore) {
		t.Fatalf("changed member timestamp did not advance: %s -> %s", firstBefore, firstAfter)
	}
	if !secondAfter.Equal(secondBefore) {
		t.Fatalf("unrelated member timestamp changed: %s -> %s", secondBefore, secondAfter)
	}
}

func TestSharedRuntimeReportsStartingDuringPlannedTransition(t *testing.T) {
	releaseStart := make(chan struct{})
	fake := &fakeSharedRuntime{
		failStartAt:  make(map[int]error),
		blockStartAt: map[int]<-chan struct{}{1: releaseStart},
	}
	hooks := fake.hooks()
	hooks.startupGrace = 0
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, hooks,
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- group.Reconcile(context.Background())
	}()
	waitFor(t, func() bool { return fake.startCount() == 1 })
	for _, tag := range []string{"proxy_a", "proxy_b"} {
		status := group.memberStatus(context.Background(), tag)
		if status.State != StateStarting || status.Error != "" {
			t.Fatalf("%s exposed a planned transition as a failure: %#v", tag, status)
		}
	}
	close(releaseStart)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if status := group.memberStatus(context.Background(), "proxy_a"); status.State != StateUp {
		t.Fatalf("completed transition did not become healthy: %#v", status)
	}
}

func TestSharedRuntimeRemainsStartingWhileRollbackStarts(t *testing.T) {
	releaseRollback := make(chan struct{})
	fake := &fakeSharedRuntime{
		failStartAt: map[int]error{2: errors.New("candidate start failed")},
		blockStartAt: map[int]<-chan struct{}{
			3: releaseRollback,
		},
	}
	hooks := fake.hooks()
	hooks.startupGrace = 0
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, hooks,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	done := make(chan error, 1)
	go func() {
		done <- group.ApplyInventory(context.Background(), next)
	}()
	waitFor(t, func() bool { return fake.startCount() == 3 })
	if status := group.memberStatus(context.Background(), "proxy_a"); status.State != StateStarting ||
		status.Error != "" {
		t.Fatalf("rollback start was exposed as a failure: %#v", status)
	}
	close(releaseRollback)
	if err := <-done; err == nil {
		t.Fatal("expected candidate failure with successful rollback")
	}
	if status := group.memberStatus(context.Background(), "proxy_a"); status.State != StateUp {
		t.Fatalf("successful rollback did not restore healthy state: %#v", status)
	}
}

func TestSharedRuntimeCrashRemovesOwnedRulesAndReconciles(t *testing.T) {
	var clockMu sync.Mutex
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	fake.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		current = current.Add(time.Second)
		return current
	}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstBefore := group.memberStatus(context.Background(), "proxy_a").UpdatedAt
	secondBefore := group.memberStatus(context.Background(), "proxy_b").UpdatedAt
	callbackRan := make(chan struct{}, 1)
	fake.mu.Lock()
	fake.onCrashRemove = func() {
		_ = group.memberStatus(context.Background(), "proxy_a")
		callbackRan <- struct{}{}
	}
	fake.mu.Unlock()

	fake.process(0).terminate(errors.New("unexpected shared crash"))
	// Receive the hook's own completion signal. Polling crashRemoveCount() and
	// then peeking at the channel with a non-blocking select was racy: the fake's
	// removeCrashRules hook publishes the counter and releases fake.mu one full
	// critical section BEFORE it invokes the callback, so the poll could observe
	// the counter while the callback body had not yet reached its send, and the
	// default branch aborted the test for a hook that was about to finish. The
	// timeout here is a diagnostic so a genuinely stuck hook cannot wedge CI; the
	// receive, not the timeout, is the synchronisation.
	select {
	case <-callbackRan:
	case <-time.After(30 * time.Second):
		t.Fatal("crash cleanup hook did not complete")
	}
	if got := fake.crashRemoveCount(); got != 1 {
		t.Fatalf("crash rule removal ran %d times, want 1", got)
	}
	for _, tag := range []string{"proxy_a", "proxy_b"} {
		status := group.memberStatus(context.Background(), tag)
		if status.State != StateDegraded || status.PID != 0 {
			t.Fatalf("%s did not report the shared crash: %#v", tag, status)
		}
	}
	if got := group.memberStatus(context.Background(), "proxy_a").UpdatedAt; !got.After(firstBefore) {
		t.Fatalf("proxy A timestamp did not advance after crash: %s -> %s", firstBefore, got)
	}
	if got := group.memberStatus(context.Background(), "proxy_b").UpdatedAt; !got.After(secondBefore) {
		t.Fatalf("proxy B timestamp did not advance after crash: %s -> %s", secondBefore, got)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.ensureCount() != 2 {
		t.Fatalf("reconcile did not restore forwarding rules, ensure calls=%d", fake.ensureCount())
	}
	if status := group.memberStatus(context.Background(), "proxy_a"); status.State != StateUp {
		t.Fatalf("reconcile did not restore the shared runtime: %#v", status)
	}
}

func TestSharedRuntimeRestartIsOneGroupRebuild(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	for _, tag := range []string{"proxy_a", "proxy_b"} {
		member, memberErr := group.Member(tag)
		if memberErr != nil {
			t.Fatal(memberErr)
		}
		if err := manager.Add(member); err != nil {
			t.Fatal(err)
		}
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restart(context.Background(), "proxy_a"); err != nil {
		t.Fatal(err)
	}
	if fake.startCount() != 2 {
		t.Fatalf("restart spawned %d processes instead of one replacement", fake.startCount())
	}
	time.Sleep(10 * time.Millisecond)
	if fake.crashRemoveCount() != 0 {
		t.Fatal("intentional replacement cleaned forwarding rules for the new generation")
	}
	statuses := manager.Statuses(context.Background())
	if statuses[0].PID == 0 || statuses[0].PID != statuses[1].PID {
		t.Fatalf("restart split the shared PID: %#v", statuses)
	}
}

func TestSharedRuntimeRestartDownMemberEnablesItInOneRebuild(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	specs := sharedRuntimeSpecs()
	specs[0].AutoStart = false
	group, err := newSharedSingBoxGroup(
		specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	for _, tag := range []string{"proxy_a", "proxy_b"} {
		member, memberErr := group.Member(tag)
		if memberErr != nil {
			t.Fatal(memberErr)
		}
		if err := manager.Add(member); err != nil {
			t.Fatal(err)
		}
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := group.memberStatus(context.Background(), "proxy_a")
	if before.State != StateDown || before.PID != 0 || before.DesiredUp {
		t.Fatalf("disabled member unexpectedly shares the active state: %#v", before)
	}
	if err := manager.Restart(context.Background(), "proxy_a"); err != nil {
		t.Fatal(err)
	}
	if fake.startCount() != 2 {
		t.Fatalf("enabling restart spawned %d processes instead of one replacement", fake.startCount())
	}
	first := group.memberStatus(context.Background(), "proxy_a")
	second := group.memberStatus(context.Background(), "proxy_b")
	if !first.DesiredUp || first.State != StateUp || first.PID == 0 || first.PID != second.PID {
		t.Fatalf("restart did not enable the logical member in the shared process: %#v / %#v", first, second)
	}
}

func TestSharedRuntimeCheckFailureDoesNotStopLiveProcess(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.check = func(data []byte) error {
		if bytesContain(data, []byte("invalid.example")) {
			return errors.New("candidate rejected")
		}
		return nil
	}
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"invalid.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected candidate validation failure")
	}
	process := fake.process(0)
	if fake.startCount() != 1 || process.stopCalls != 0 || !process.Alive() {
		t.Fatal("validation failure disturbed the live shared process")
	}
	if got := group.Inventory()[0].OutboundJSON; got != sharedRuntimeSpecs()[0].OutboundJSON {
		t.Fatal("validation failure committed the candidate inventory")
	}
}

func TestSharedRuntimeChecksExactDesiredSubsetBeforeStopping(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	specs := sharedRuntimeSpecs()
	specs[1].AutoStart = false
	group, err := newSharedSingBoxGroup(
		specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.check = func(data []byte) error {
		if bytesContain(data, []byte("candidate.example")) &&
			!bytesContain(data, []byte("proxy-out-proxy_b")) {
			return errors.New("active subset rejected")
		}
		return nil
	}
	next := append([]TransportSpec(nil), specs...)
	next[0].OutboundJSON = `{"type":"vless","server":"candidate.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected exact desired subset validation failure")
	}
	process := fake.process(0)
	if fake.startCount() != 1 || process.stopCalls != 0 || !process.Alive() {
		t.Fatal("subset validation failure disturbed the live process")
	}
}

func TestSharedRuntimeFastPathDoesNotCommitWhenForwardingRulesFail(t *testing.T) {
	fake := &fakeSharedRuntime{
		failStartAt:  make(map[int]error),
		failEnsureAt: map[int]error{2: errors.New("firewall unavailable")},
	}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].DisplayName = "presentation-only change"
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected forwarding rule failure")
	}
	if fake.startCount() != 1 || !fake.process(0).Alive() {
		t.Fatal("fast-path firewall failure disturbed the live process")
	}
	for _, spec := range group.Inventory() {
		if spec.Tag == next[0].Tag && spec.DisplayName != "" {
			t.Fatal("fast-path firewall failure committed the candidate inventory")
		}
	}
}

func TestSharedRuntimeReattachesLiveProcessWhenStopFails(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	process := fake.process(0)
	process.mu.Lock()
	process.stopErr = errors.New("cannot signal process")
	process.keepAlive = true
	process.mu.Unlock()
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected failed stop to abort the update")
	}
	status := group.memberStatus(context.Background(), "proxy_a")
	if fake.startCount() != 1 || !process.Alive() || status.State != StateUp || status.PID != 1001 {
		t.Fatalf("live process ownership was lost after stop failure: %#v", status)
	}
}

func TestSharedRuntimeRollsBackPreviousProcessWhenCandidateCannotStart(t *testing.T) {
	fake := &fakeSharedRuntime{
		failStartAt: map[int]error{2: errors.New("candidate start failed")},
	}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected failed update to report rollback")
	}
	if fake.startCount() != 3 {
		t.Fatalf("expected candidate plus one rollback start, got %d", fake.startCount())
	}
	status := group.memberStatus(context.Background(), "proxy_a")
	if status.State != StateUp || status.PID != 1003 {
		t.Fatalf("previous runtime was not restored: %#v", status)
	}
	if status.Error != "" {
		t.Fatalf("successful rollback left a persistent false runtime error: %q", status.Error)
	}
	if got := group.Inventory()[0].OutboundJSON; got != sharedRuntimeSpecs()[0].OutboundJSON {
		t.Fatal("failed candidate replaced the previous inventory")
	}
}

func TestSharedRuntimeMarksRollbackDegradedWhenOldRulesCannotBeRestored(t *testing.T) {
	fake := &fakeSharedRuntime{
		failStartAt: make(map[int]error),
		failEnsureAt: map[int]error{
			2: errors.New("candidate forwarding failed"),
			3: errors.New("restore forwarding failed"),
		},
	}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected rollback rule failure")
	}
	status := group.memberStatus(context.Background(), "proxy_a")
	if status.State != StateDegraded || status.PID != 1003 ||
		!bytesContain([]byte(status.Error), []byte("restore previous shared sing-box forwarding rules")) {
		t.Fatalf("incomplete rollback was reported healthy: %#v", status)
	}
}

func TestSharedRuntimeRejectsCandidateThatCrashesDuringStartupGrace(t *testing.T) {
	fake := &fakeSharedRuntime{
		failStartAt: make(map[int]error),
		crashAt:     map[int]time.Duration{2: 5 * time.Millisecond},
	}
	hooks := fake.hooks()
	hooks.startupGrace = 20 * time.Millisecond
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, hooks,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := sharedRuntimeSpecs()
	next[0].OutboundJSON = `{"type":"vless","server":"new.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err == nil {
		t.Fatal("expected unstable candidate to be rolled back")
	}
	if fake.startCount() != 3 {
		t.Fatalf("expected candidate plus rollback process, got %d starts", fake.startCount())
	}
	status := group.memberStatus(context.Background(), "proxy_a")
	if status.State != StateUp || status.PID != 1003 {
		t.Fatalf("startup crash escaped transactional rollback: %#v", status)
	}
}

func TestManagerRegistersEmptySharedGroupForFirstProxyCRUD(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		nil, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	if err := manager.SetSharedGroup(group); err != nil {
		t.Fatal(err)
	}
	if manager.SharedGroup() != group {
		t.Fatal("empty shared runtime was not discoverable before the first proxy was created")
	}
}

func TestManagerClosesSharedGroupWithoutRegisteredMembers(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	group, err := newSharedSingBoxGroup(
		sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	if err := manager.SetSharedGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.process(0).Alive() {
		t.Fatal("empty manager registry leaked its owned shared process")
	}
}

func TestSupervisorSharedHealthIncludesPerProxyRoutingVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"outbounds":[{"interfaces":[` +
			`{"interface_name":"vless1","status":"failed","detail":"probe failed"}` +
			`]}]}`))
	}))
	defer server.Close()

	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	spec := sharedRuntimeSpecs()[0]
	group, err := newSharedSingBoxGroup(
		[]TransportSpec{spec},
		"sing-box",
		t.TempDir(),
		RoutingHealthEndpoint{URL: server.URL},
		fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	member, err := group.Member(spec.Tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(member); err != nil {
		t.Fatal(err)
	}
	supervisor := newSupervisor(manager, time.Second, time.Second, time.Minute)
	supervisor.Register(spec)
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		healthy := supervisor.groupMembersHealthy(context.Background(), group.Key())
		if attempt < 3 && !healthy {
			t.Fatalf("routing health degraded before the existing threshold at attempt %d", attempt)
		}
		if attempt == 3 && healthy {
			t.Fatal("shared supervisor ignored a repeatedly failed per-proxy routing verdict")
		}
	}
}

func TestSupervisorReconcilesSharedGroupOnlyOnce(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	specs := sharedRuntimeSpecs()
	group, err := newSharedSingBoxGroup(
		specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	supervisor := newSupervisor(manager, time.Millisecond, time.Millisecond, 5*time.Millisecond)
	for _, spec := range specs {
		member, memberErr := group.Member(spec.Tag)
		if memberErr != nil {
			t.Fatal(memberErr)
		}
		if err := manager.Add(member); err != nil {
			t.Fatal(err)
		}
		supervisor.Register(spec)
	}
	if len(supervisor.groupStates) != 1 || len(supervisor.states) != 0 {
		t.Fatalf("shared members were registered as independent retry loops")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go supervisor.Run(ctx)
	waitFor(t, func() bool {
		return fake.startCount() == 1 && group.Healthy()
	})
	time.Sleep(5 * time.Millisecond)
	if fake.startCount() != 1 {
		t.Fatalf("shared supervisor performed duplicate starts: %d", fake.startCount())
	}
}

func bytesContain(value, fragment []byte) bool {
	return len(fragment) == 0 || bytesIndex(value, fragment) >= 0
}

func bytesIndex(value, fragment []byte) int {
	for index := 0; index+len(fragment) <= len(value); index++ {
		matched := true
		for offset := range fragment {
			if value[index+offset] != fragment[offset] {
				matched = false
				break
			}
		}
		if matched {
			return index
		}
	}
	return -1
}
