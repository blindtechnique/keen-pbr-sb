package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestSingBoxServicePreservesDisabledMembersAndBootPreferences(t *testing.T) {
	s, group, fake, state := sharedRecoveryFixture(t, http.StatusOK, "active")
	if err := s.manager.SetSharedGroup(group); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := group.ApplyPower(ctx, "proxy_b", false, false); err != nil {
		t.Fatal(err)
	}
	before := fake.startCount()
	if err := s.ServiceAction(ctx, "restart"); err != nil {
		t.Fatal(err)
	}
	if fake.startCount() != before+1 {
		t.Fatal("shared process restarted more than once")
	}
	for _, action := range []string{"down", "down", "up", "restart"} {
		if err := s.ServiceAction(ctx, action); err != nil {
			t.Fatal(err)
		}
		if action == "down" {
			s.reconcileGroup(ctx, group.Key(), state)
			if group.HasDesired() || group.memberStatus(ctx, "proxy_a").State != StateDown {
				t.Fatal("supervisor undid service stop")
			}
		}
		if group.memberStatus(ctx, "proxy_b").DesiredUp {
			t.Fatal("disabled member resurrected")
		}
		group.mu.RLock()
		aBoot, bBoot := group.specs["proxy_a"].AutoStart, group.specs["proxy_b"].AutoStart
		group.mu.RUnlock()
		if !aBoot || bBoot {
			t.Fatal("service action changed boot preferences")
		}
	}
}

func TestSingBoxServiceRestartHonorsStopEvenWhenStartValidationFails(t *testing.T) {
	s, group, fake, _ := sharedRecoveryFixture(t, http.StatusOK, "active")
	_ = s.manager.SetSharedGroup(group)
	process := fake.process(0)
	fake.mu.Lock()
	fake.check = func([]byte) error { return errors.New("invalid replacement configuration") }
	fake.mu.Unlock()
	if err := s.ServiceAction(context.Background(), "restart"); err == nil {
		t.Fatal("failed start was reported as success")
	}
	if process.Alive() {
		t.Fatal("validation vetoed the explicit restart's stop")
	}
}

func TestSingBoxManualStopPreemptsBackgroundValidation(t *testing.T) {
	s, group, fake, state := sharedRecoveryFixture(t, http.StatusOK, "active")
	_ = s.manager.SetSharedGroup(group)
	fake.process(0).terminate(errors.New("crash"))
	started := make(chan struct{})
	group.hooks.checkConfig = func(ctx context.Context, _, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	// Bypass the intentional first-loss grace period for this cancellation test.
	s.mu.Lock()
	state.attempts = 1
	state.observedUp = false
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.reconcileGroup(context.Background(), group.Key(), state); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background check did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.ServiceAction(ctx, "down"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("background check blocked manual stop")
	}
	if group.HasDesired() {
		t.Fatal("manual stop was lost")
	}
}

func TestSingBoxManualStopPreemptsBackgroundRuleRepair(t *testing.T) {
	s, group, _, state := sharedRecoveryFixture(t, http.StatusOK, "active")
	_ = s.manager.SetSharedGroup(group)
	started := make(chan struct{})
	group.hooks.ensureRules = func(ctx context.Context, _ []TransportSpec) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan struct{})
	go func() { s.reconcileGroup(context.Background(), group.Key(), state); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background rule check did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.ServiceAction(ctx, "down"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("rule repair blocked manual stop")
	}
	if group.HasDesired() {
		t.Fatal("manual stop was lost")
	}
}

func TestSingBoxIsolatedServiceRespectsManualChangesWhileStopped(t *testing.T) {
	manager := NewManager()
	s := newSupervisor(manager, time.Second, time.Hour, time.Hour)
	a, b := &supervisorFake{tag: "a"}, &supervisorFake{tag: "b"}
	for _, member := range []*supervisorFake{a, b} {
		if err := manager.Add(member); err != nil {
			t.Fatal(err)
		}
		s.Register(TransportSpec{Tag: member.tag, Type: "sing-box", AutoStart: true})
	}
	ctx := context.Background()
	for _, action := range []string{"up", "restart", "down", "down"} {
		if err := s.ServiceAction(ctx, action); err != nil {
			t.Fatal(err)
		}
	}
	// New user intent wins over the resume snapshot taken by service stop.
	if err := s.Down(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.ServiceAction(ctx, "up"); err != nil {
		t.Fatal(err)
	}
	if err := s.ServiceAction(ctx, "restart"); err != nil {
		t.Fatal(err)
	}
	aStarted, _ := a.snapshot()
	bStarted, bStarts := b.snapshot()
	if !aStarted || bStarted || bStarts != 2 {
		t.Fatalf("isolated service lost member intent: a=%v b=%v b starts=%d", aStarted, bStarted, bStarts)
	}
}

type pendingServiceStart struct {
	supervisorFake
	entered chan struct{}
}

func (p *pendingServiceStart) Up(ctx context.Context) error {
	close(p.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestSingBoxIsolatedManualStopPreemptsBackgroundStart(t *testing.T) {
	manager := NewManager()
	member := &pendingServiceStart{supervisorFake: supervisorFake{tag: "pending"}, entered: make(chan struct{})}
	if err := manager.Add(member); err != nil {
		t.Fatal(err)
	}
	s := newSupervisor(manager, time.Second, time.Hour, time.Hour)
	s.Register(TransportSpec{Tag: member.tag, Type: "sing-box", AutoStart: true})
	done := make(chan struct{})
	go func() { s.reconcileOne(context.Background(), member.tag, s.stateFor(member.tag)); close(done) }()
	select {
	case <-member.entered:
	case <-time.After(time.Second):
		t.Fatal("background start did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.ServiceAction(ctx, "down"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("background start blocked manual stop")
	}
	status, _ := s.Status(ctx, member.tag)
	if status.DesiredUp {
		t.Fatal("manual stop was lost")
	}
}
