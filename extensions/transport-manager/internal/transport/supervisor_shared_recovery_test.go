package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sharedRecoveryFixture(t *testing.T, httpStatus int, verdict string) (*Supervisor, *SharedSingBoxGroup, *fakeSharedRuntime, *groupRetryState) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(httpStatus)
		_, _ = w.Write([]byte(`{"outbounds":[{"interfaces":[` +
			`{"interface_name":"vless1","status":"` + verdict + `","detail":"unsupported usage for uTLS"},` +
			`{"interface_name":"vless2","status":"active"}]}]}`))
	}))
	t.Cleanup(server.Close)
	fake := &fakeSharedRuntime{}
	specs := sharedRuntimeSpecs()
	specs[0].OutboundJSON = `{"type":"hysteria2","server":"bad.example","server_port":443,"password":"example","tls":{"enabled":true}}`
	group, err := newSharedSingBoxGroup(specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{URL: server.URL}, fake.hooks())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Close(context.Background()) })
	manager := NewManager()
	supervisor := newSupervisor(manager, time.Second, time.Hour, time.Hour)
	for _, spec := range specs {
		member, err := group.Member(spec.Tag)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Add(member); err != nil {
			t.Fatal(err)
		}
		supervisor.Register(spec)
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, state := supervisor.groupStateForTag(specs[0].Tag)
	return supervisor, group, fake, state
}

func TestSupervisorSharedRemoteFailureKeepsHealthyMembersRunning(t *testing.T) {
	for _, verdict := range []string{"failed", "degraded", "unavailable"} {
		t.Run(verdict, func(t *testing.T) {
			supervisor, group, fake, state := sharedRecoveryFixture(t, http.StatusOK, verdict)
			original := fake.process(0)
			// Browser polling and supervisor passes must not turn repeated remote
			// failures into process restarts, even after the status threshold.
			for attempt := 1; attempt <= 12; attempt++ {
				bad, err := supervisor.Status(context.Background(), "proxy_a")
				if err != nil {
					t.Fatal(err)
				}
				good, err := supervisor.Status(context.Background(), "proxy_b")
				if err != nil {
					t.Fatal(err)
				}
				supervisor.reconcileGroup(context.Background(), group.Key(), state)
				if attempt >= 3 && (bad.State != StateDegraded || !strings.Contains(bad.Error, "unsupported usage for uTLS")) {
					t.Fatalf("failed Hysteria health was hidden: %#v", bad)
				}
				if good.State != StateUp || good.PID != original.PID() || fake.startCount() != 1 || !original.Alive() {
					t.Fatalf("remote failure restarted a healthy sibling at attempt %d: %#v, starts=%d", attempt, good, fake.startCount())
				}
			}
			if state.attempts != 0 || !state.observedUp {
				t.Fatalf("remote failure scheduled shared recovery: attempts=%d observedUp=%v", state.attempts, state.observedUp)
			}
			// Explicitly disabling one member changes the shared configuration
			// once. The failed member must not cause any subsequent replacement.
			if err := supervisor.Down(context.Background(), "proxy_a"); err != nil {
				t.Fatal(err)
			}
			if fake.startCount() != 2 || original.Alive() {
				t.Fatalf("manual down did not replace the shared configuration once: starts=%d", fake.startCount())
			}
			for attempt := 0; attempt < 6; attempt++ {
				supervisor.reconcileGroup(context.Background(), group.Key(), state)
				bad, _ := supervisor.Status(context.Background(), "proxy_a")
				good, _ := supervisor.Status(context.Background(), "proxy_b")
				if bad.DesiredUp || bad.State != StateDown || good.State != StateUp || good.PID != fake.process(1).PID() || fake.startCount() != 2 {
					t.Fatalf("disabled remote member disturbed its sibling: %#v / %#v, starts=%d", bad, good, fake.startCount())
				}
			}
		})
	}
}

func TestSupervisorSharedRecoversLocalRuntimeLoss(t *testing.T) {
	for _, loss := range []string{"process", "interface"} {
		t.Run(loss, func(t *testing.T) {
			supervisor, group, fake, state := sharedRecoveryFixture(t, http.StatusOK, "failed")
			supervisor.reconcileGroup(context.Background(), group.Key(), state)
			if loss == "process" {
				fake.process(0).terminate(errors.New("shared process crashed"))
			} else {
				fake.mu.Lock()
				fake.missingInterface = "vless1"
				fake.mu.Unlock()
				start := group.hooks.startProcess
				group.hooks.startProcess = func(binary, config, logPath string) (sharedProcess, error) {
					process, err := start(binary, config, logPath)
					fake.mu.Lock()
					fake.missingInterface = ""
					fake.mu.Unlock()
					return process, err
				}
			}
			if group.Healthy() {
				t.Fatal("actual local runtime loss was not detected")
			}
			supervisor.reconcileGroup(context.Background(), group.Key(), state)
			if fake.startCount() != 1 || state.attempts != 1 || state.observedUp || state.next.IsZero() {
				t.Fatal("local runtime loss did not retain the existing recovery backoff")
			}
			// Model expiry of the existing retry delay without wall-clock sleeps.
			supervisor.mu.Lock()
			state.next = time.Time{}
			supervisor.mu.Unlock()
			supervisor.reconcileGroup(context.Background(), group.Key(), state)
			if fake.startCount() != 2 || !fake.process(1).Alive() || !group.Healthy() {
				t.Fatalf("local %s loss did not recover the shared runtime: starts=%d", loss, fake.startCount())
			}
		})
	}
}

func TestSupervisorSharedDoesNotRestartForUnknownOrHealthyRoutingHealth(t *testing.T) {
	for _, test := range []struct {
		name       string
		httpStatus int
		verdict    string
	}{
		{"unknown", http.StatusOK, "unknown"},
		{"unavailable", http.StatusServiceUnavailable, "failed"},
		{"healthy", http.StatusOK, "healthy"},
		{"active", http.StatusOK, "active"},
		{"backup", http.StatusOK, "backup"},
	} {
		t.Run(test.name, func(t *testing.T) {
			supervisor, group, fake, state := sharedRecoveryFixture(t, test.httpStatus, test.verdict)
			for attempt := 0; attempt < 5; attempt++ {
				supervisor.reconcileGroup(context.Background(), group.Key(), state)
			}
			if fake.startCount() != 1 || !fake.process(0).Alive() {
				t.Fatalf("%s routing health restarted the shared process", test.name)
			}
		})
	}
}

func TestSupervisorSharedMissingRegistryMemberDoesNotRestartHealthyProcess(t *testing.T) {
	supervisor, group, fake, state := sharedRecoveryFixture(t, http.StatusOK, "failed")
	if err := supervisor.manager.Forget("proxy_a"); err != nil {
		t.Fatal(err)
	}
	// Inventory replacement briefly updates the shared group and registry in
	// separate steps. A missing registry entry is not a remote-health verdict.
	supervisor.reconcileGroup(context.Background(), group.Key(), state)
	if fake.startCount() != 1 || !fake.process(0).Alive() {
		t.Fatal("temporary registry absence restarted a healthy shared process")
	}
}
