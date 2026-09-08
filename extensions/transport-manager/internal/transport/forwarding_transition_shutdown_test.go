package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type transitionEnsureRunner struct {
	*fakeFirewallRunner
	block   func([]string) bool
	blocked bool
}

func (r *transitionEnsureRunner) Run(ctx context.Context, binary string, args []string) firewallCommandResult {
	if r.block(args) {
		r.blocked = true
		<-ctx.Done()
		return firewallCommandResult{exitCode: -1, err: ctx.Err()}
	}
	return r.fakeFirewallRunner.Run(ctx, binary, args)
}

func TestForwardingEnsureContextCancellationIncludesMutex(t *testing.T) {
	for _, alreadyCanceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "busy mutex", true: "before ensure"}[alreadyCanceled], func(t *testing.T) {
			runner := newFakeFirewallRunner()
			manager := newForwardingRuleManager(runner)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if alreadyCanceled {
				cancel()
			} else {
				manager.mu.Lock()
				defer manager.mu.Unlock()
			}
			started := time.Now()
			err := manager.ensureInterfacesContext(ctx, []string{"vpn1"})
			if !errors.Is(err, ctx.Err()) || ctx.Err() == nil {
				t.Fatalf("ensure error = %v, context error = %v", err, ctx.Err())
			}
			if time.Since(started) > time.Second {
				t.Fatal("ensure waited beyond the shutdown budget for the mutex")
			}
			if len(runner.calls) != 0 {
				t.Fatal("cancelled ensure inspected or changed forwarding rules")
			}
		})
	}
}

func TestForwardingEnsureContextCancelsCommandPhases(t *testing.T) {
	for _, phase := range []string{"wait probe", "bare wait probe", "marked inspection", "legacy inspection", "append", "appended verification", "count", "dedupe delete", "scaffold probe"} {
		t.Run(phase, func(t *testing.T) {
			fake := newFakeFirewallRunner()
			marked := forwardingRuleArgs("vpn1")
			if phase == "count" || phase == "dedupe delete" {
				fake.setRuleCount("iptables", marked, 2)
			}
			if phase == "bare wait probe" {
				fake.waitValueSupported = false
			}
			if phase == "scaffold probe" {
				fake.scripted[fakeCommandKey("iptables", "-C", marked)] = []firewallCommandResult{
					{exitCode: 2, output: "No chain/target/match by that name"},
				}
			}
			appended := false
			runner := &transitionEnsureRunner{fakeFirewallRunner: fake}
			runner.block = func(args []string) bool {
				command := strings.Join(args, " ")
				switch phase {
				case "wait probe":
					return command == "-w 1 -S"
				case "bare wait probe":
					return command == "-w -S"
				case "marked inspection":
					return strings.Contains(command, "-C FORWARD") && strings.Contains(command, "--comment")
				case "legacy inspection":
					return strings.Contains(command, "-C FORWARD") && !strings.Contains(command, "--comment")
				case "append":
					return strings.Contains(command, "-A FORWARD")
				case "appended verification":
					if strings.Contains(command, "-A FORWARD") {
						appended = true
					}
					return appended && strings.Contains(command, "-C FORWARD")
				case "count", "scaffold probe":
					return strings.Contains(command, "-S FORWARD")
				case "dedupe delete":
					return strings.Contains(command, "-D FORWARD")
				}
				return false
			}
			manager := newForwardingRuleManager(runner)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := manager.ensureInterfacesContext(ctx, []string{"vpn1", "vpn2"})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("ensure error = %v", err)
			}
			if !runner.blocked {
				t.Fatal("fixture did not reach the intended command")
			}
			if time.Since(started) > time.Second {
				t.Fatal("ensure replaced the shared shutdown deadline with a command timeout")
			}
		})
	}
}

func TestForwardingEnsureContextCancelsRetryAndScaffoldWaits(t *testing.T) {
	for _, phase := range []string{"xtables retry", "scaffold retry", "scaffold stabilization"} {
		t.Run(phase, func(t *testing.T) {
			fake := newFakeFirewallRunner()
			markedKey := fakeCommandKey("iptables", "-C", forwardingRuleArgs("vpn1"))
			missing := firewallCommandResult{exitCode: 2, output: "No chain/target/match by that name"}
			if phase == "xtables retry" {
				fake.scripted[markedKey] = []firewallCommandResult{{exitCode: 4, output: "Another app is holding the xtables lock"}}
			} else {
				fake.scripted[markedKey] = []firewallCommandResult{missing}
				if phase == "scaffold retry" {
					fake.scripted[fakeCommandKey("iptables", "-S", []string{"FORWARD"})] = []firewallCommandResult{missing}
				}
			}
			manager := newForwardingRuleManager(fake)
			manager.retryDelays = []time.Duration{time.Hour}
			manager.scaffoldRetryDelays = []time.Duration{time.Hour}
			manager.scaffoldStableDelay = time.Hour
			manager.sleep = func(time.Duration) { t.Error("ensure used an uncancellable delay") }
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := manager.ensureInterfacesContext(ctx, []string{"vpn1"})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("ensure error = %v", err)
			}
			if time.Since(started) > time.Second {
				t.Fatal("ensure did not cancel its retry delay")
			}
			if fake.ruleCount("iptables", forwardingRuleArgs("vpn1")) != 0 {
				t.Fatal("ensure appended a rule after its retry was cancelled")
			}
		})
	}
}
