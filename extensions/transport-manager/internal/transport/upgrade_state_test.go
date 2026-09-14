package transport

import (
	"context"
	"strings"
	"testing"
)

func TestSharedUpgradeIntentAppliedBeforeFirstProcessAndSurvivesInventoryRefresh(t *testing.T) {
	specs := sharedRuntimeSpecs()
	// This member was manually started despite disabled auto_start.
	specs[1].AutoStart = false
	fake := &fakeSharedRuntime{}
	group, err := newSharedSingBoxGroup(specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks())
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close(context.Background())
	group.restoreInitialDesired(map[string]bool{"proxy_a": false, "proxy_b": true})
	if fake.startCount() != 0 {
		t.Fatal("restore launched a process before applying intent")
	}
	if err := group.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stopped := group.memberStatus(context.Background(), "proxy_a"); stopped.DesiredUp || stopped.PID != 0 || stopped.State != StateDown {
		t.Fatalf("manually stopped member started: %#v", stopped)
	}
	if started := group.memberStatus(context.Background(), "proxy_b"); !started.DesiredUp || started.State != StateUp {
		t.Fatalf("manually started member was lost: %#v", started)
	}
	if group.activeTags["proxy_a"] || !group.activeTags["proxy_b"] || strings.Contains(string(group.activeData), "a.example") {
		t.Fatal("the first shared process contained the disabled member")
	}
	if !group.specs["proxy_a"].AutoStart || group.specs["proxy_b"].AutoStart {
		t.Fatal("upgrade intent overwrote auto_start preferences")
	}
	next := append([]TransportSpec(nil), specs...)
	next[0].OutboundJSON = `{"type":"vless","server":"changed.example","server_port":443,"uuid":"example"}`
	if err := group.ApplyInventory(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if group.memberStatus(context.Background(), "proxy_a").DesiredUp || !group.memberStatus(context.Background(), "proxy_b").DesiredUp {
		t.Fatal("subscription refresh reset upgraded manual intent")
	}
	// An ordinary new process deliberately starts from the saved preferences.
	ordinary, err := newSharedSingBoxGroup(specs, "sing-box", t.TempDir(), RoutingHealthEndpoint{}, fake.hooks())
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close(context.Background())
	if !ordinary.desired["proxy_a"] || ordinary.desired["proxy_b"] {
		t.Fatal("normal startup no longer follows auto_start")
	}
}

func TestIsolatedUpgradeIntentDoesNotLaunchStoppedMember(t *testing.T) {
	manager := NewManager()
	fake := &supervisorFake{tag: "stopped"}
	if err := manager.Add(fake); err != nil {
		t.Fatal(err)
	}
	supervisor := NewSupervisor(manager)
	supervisor.RegisterWithDesired(TransportSpec{Tag: "stopped", Type: "sing-box", AutoStart: true}, false)
	status, err := supervisor.Status(context.Background(), "stopped")
	if err != nil || status.DesiredUp {
		t.Fatalf("stopped intent was not restored: %#v, %v", status, err)
	}
	if _, calls := fake.snapshot(); calls != 0 {
		t.Fatal("initial registration briefly started the stopped member")
	}
}
