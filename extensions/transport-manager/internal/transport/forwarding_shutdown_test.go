package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

type shutdownFirewallRunner struct{ calls int }

func (*shutdownFirewallRunner) LookPath(binary string) (string, error) {
	if binary == "iptables" {
		return binary, nil
	}
	return "", errors.New("not installed")
}

func (r *shutdownFirewallRunner) Run(ctx context.Context, _ string, _ []string) firewallCommandResult {
	r.calls++
	<-ctx.Done()
	return firewallCommandResult{exitCode: -1, err: ctx.Err()}
}

func TestForwardingCleanupSharesShutdownDeadlineAcrossCommands(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "wait probe", true: "delete rule"}[cached], func(t *testing.T) {
			runner := &shutdownFirewallRunner{}
			manager := newForwardingRuleManager(runner)
			if cached {
				manager.waitSupport["iptables"] = xtablesWaitWithTimeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := manager.cleanupInterfacesContext(ctx, []string{"vpn1", "vpn2", "vpn3"}, true)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cleanup error = %v", err)
			}
			if time.Since(started) > time.Second {
				t.Fatal("cleanup used a new timeout for each rule")
			}
			if runner.calls != 1 {
				t.Fatalf("ran %d commands after shutdown deadline", runner.calls)
			}
		})
	}
}

func TestForwardingCleanupDeadlineIncludesWaitingForFirewallMutex(t *testing.T) {
	manager := newForwardingRuleManager(newFakeFirewallRunner())
	manager.mu.Lock()
	defer manager.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.cleanupInterfacesContext(ctx, []string{"vpn1"}, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestSharedRuntimeClosePassesShutdownDeadlineToFirewallCleanup(t *testing.T) {
	fake := &fakeSharedRuntime{failStartAt: make(map[int]error)}
	hooks := fake.hooks()
	group, err := newSharedSingBoxGroup(sharedRuntimeSpecs(), "sing-box", t.TempDir(), RoutingHealthEndpoint{}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if err = group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	group.hooks.removeRules = func(ctx context.Context, _ map[string]bool, _ map[string]TransportSpec) error {
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = group.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error = %v", err)
	}
	if fake.process(0).Alive() {
		t.Fatal("sing-box was not stopped before firewall cleanup")
	}
}
