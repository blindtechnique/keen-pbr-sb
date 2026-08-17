package transport

import (
	"context"
	"log"
	"sync"
	"time"
)

type retryState struct {
	opMu          sync.Mutex
	desired       bool
	attempts      int
	next          time.Time
	inFlight      bool
	observedUp    bool
	healthySince  time.Time
	nextRuleCheck time.Time
}

type Supervisor struct {
	manager             *Manager
	mu                  sync.Mutex
	states              map[string]*retryState
	groupStates         map[string]*groupRetryState
	tagGroups           map[string]string
	interval            time.Duration
	baseBackoff         time.Duration
	maxBackoff          time.Duration
	stablePeriod        time.Duration
	runtimeRuleInterval time.Duration
}

type groupRetryState struct {
	opMu          sync.Mutex
	runtime       supervisorGroup
	attempts      int
	next          time.Time
	inFlight      bool
	observedUp    bool
	healthySince  time.Time
	nextRuleCheck time.Time
}

// Implemented by transports that own firewall state which the firmware may
// drop from under them.
type runtimeRuleEnforcer interface {
	EnsureRuntimeRules() error
}

func NewSupervisor(manager *Manager) *Supervisor {
	return newSupervisor(manager, 5*time.Second, 2*time.Second, 2*time.Minute)
}

func newSupervisor(manager *Manager, interval, baseBackoff, maxBackoff time.Duration) *Supervisor {
	return &Supervisor{
		manager: manager, states: make(map[string]*retryState),
		groupStates: make(map[string]*groupRetryState), tagGroups: make(map[string]string),
		interval:    interval,
		baseBackoff: baseBackoff, maxBackoff: maxBackoff, stablePeriod: 30 * time.Second,
		runtimeRuleInterval: 30 * time.Second,
	}
}

func (s *Supervisor) Register(spec TransportSpec) {
	if spec.Type == "native" {
		s.Forget(spec.Tag)
		return
	}
	if managed, ok := s.manager.Get(spec.Tag); ok {
		if grouped, ok := managed.(groupedTransport); ok {
			group := grouped.SupervisorGroup()
			key := group.Key()
			s.mu.Lock()
			delete(s.states, spec.Tag)
			s.tagGroups[spec.Tag] = key
			state, exists := s.groupStates[key]
			if !exists {
				state = &groupRetryState{runtime: group}
				s.groupStates[key] = state
			}
			s.mu.Unlock()
			return
		}
	}
	s.mu.Lock()
	state, exists := s.states[spec.Tag]
	if !exists {
		state = &retryState{}
		s.states[spec.Tag] = state
	}
	s.mu.Unlock()
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[spec.Tag] != state {
		return
	}
	state.desired = spec.AutoStart
	state.attempts = 0
	state.next = time.Time{}
	state.observedUp = false
	state.healthySince = time.Time{}
	state.nextRuleCheck = time.Time{}
}

func (s *Supervisor) Forget(tag string) {
	s.mu.Lock()
	if key, grouped := s.tagGroups[tag]; grouped {
		delete(s.tagGroups, tag)
		inUse := false
		for _, candidate := range s.tagGroups {
			if candidate == key {
				inUse = true
				break
			}
		}
		if !inUse {
			delete(s.groupStates, key)
		}
		s.mu.Unlock()
		return
	}
	state := s.states[tag]
	s.mu.Unlock()
	if state == nil {
		return
	}
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.mu.Lock()
	if s.states[tag] == state {
		delete(s.states, tag)
	}
	s.mu.Unlock()
}

func (s *Supervisor) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

func (s *Supervisor) reconcile(ctx context.Context) {
	now := time.Now()
	s.mu.Lock()
	type workItem struct {
		tag   string
		state *retryState
	}
	var work []workItem
	for tag, state := range s.states {
		if state.desired && !state.inFlight && (state.next.IsZero() || !now.Before(state.next)) {
			state.inFlight = true
			work = append(work, workItem{tag: tag, state: state})
		}
	}
	type groupWorkItem struct {
		key   string
		state *groupRetryState
	}
	var groupWork []groupWorkItem
	for key, state := range s.groupStates {
		if state.runtime.HasDesired() && !state.inFlight &&
			(state.next.IsZero() || !now.Before(state.next)) {
			state.inFlight = true
			groupWork = append(groupWork, groupWorkItem{key: key, state: state})
		}
	}
	s.mu.Unlock()
	for _, item := range work {
		go s.reconcileOne(ctx, item.tag, item.state)
	}
	for _, item := range groupWork {
		go s.reconcileGroup(ctx, item.key, item.state)
	}
}

func (s *Supervisor) reconcileGroup(ctx context.Context, key string, state *groupRetryState) {
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.mu.Lock()
	current := s.groupStates[key]
	active := current == state && state.runtime.HasDesired()
	s.mu.Unlock()
	if !active {
		s.releaseGroup(key, state)
		return
	}
	now := time.Now()
	if state.runtime.Healthy() && s.groupMembersHealthy(ctx, key) {
		if s.groupRuleCheckDue(key, state, now) {
			if err := state.runtime.EnsureRuntimeRules(); err != nil {
				log.Printf("transport group %s: restore forwarding rules: %v", key, err)
			}
		}
		s.recordGroupHealthy(key, state)
		return
	}
	if s.recordGroupLoss(key, state) {
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := state.runtime.Reconcile(operationCtx)
	s.recordGroupAttempt(key, state, err)
}

// groupMembersHealthy preserves the existing per-transport routing-health
// semantics in shared mode. Process and TUN liveness are group-owned, while an
// individual proxy may still be alive but unable to carry traffic. The member
// Status implementation applies the same three-failure threshold used by
// isolated sing-box before a coordinated restart is scheduled.
func (s *Supervisor) groupMembersHealthy(ctx context.Context, key string) bool {
	s.mu.Lock()
	tags := make([]string, 0)
	for tag, candidate := range s.tagGroups {
		if candidate == key {
			tags = append(tags, tag)
		}
	}
	s.mu.Unlock()
	for _, tag := range tags {
		status, err := s.manager.Status(ctx, tag)
		if err != nil {
			return false
		}
		if status.DesiredUp && status.State != StateUp {
			return false
		}
	}
	return true
}

func (s *Supervisor) releaseGroup(key string, expected *groupRetryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.groupStates[key]; state == expected {
		state.inFlight = false
	}
}

func (s *Supervisor) groupRuleCheckDue(key string, expected *groupRetryState, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.groupStates[key]
	if state != expected || now.Before(state.nextRuleCheck) {
		return false
	}
	state.nextRuleCheck = now.Add(s.runtimeRuleInterval)
	return true
}

func (s *Supervisor) recordGroupHealthy(key string, expected *groupRetryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.groupStates[key]
	if state != expected {
		return
	}
	state.inFlight = false
	state.next = time.Time{}
	if !state.observedUp {
		state.observedUp = true
		state.healthySince = time.Now()
	}
	if time.Since(state.healthySince) >= s.stablePeriod {
		state.attempts = 0
	}
}

func (s *Supervisor) recordGroupLoss(key string, expected *groupRetryState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.groupStates[key]
	if state != expected || !state.observedUp {
		return false
	}
	state.observedUp = false
	state.healthySince = time.Time{}
	state.nextRuleCheck = time.Time{}
	s.scheduleGroupRetry(state)
	return true
}

func (s *Supervisor) recordGroupAttempt(key string, expected *groupRetryState, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.groupStates[key]
	if state != expected {
		return
	}
	state.inFlight = false
	if err == nil {
		state.next = time.Time{}
		state.observedUp = true
		state.healthySince = time.Now()
		return
	}
	state.observedUp = false
	state.healthySince = time.Time{}
	s.scheduleGroupRetry(state)
}

func (s *Supervisor) scheduleGroupRetry(state *groupRetryState) {
	state.inFlight = false
	state.attempts++
	backoff := s.baseBackoff
	for i := 1; i < state.attempts && backoff < s.maxBackoff; i++ {
		backoff *= 2
		if backoff > s.maxBackoff {
			backoff = s.maxBackoff
		}
	}
	state.next = time.Now().Add(backoff)
}

func (s *Supervisor) reconcileOne(ctx context.Context, tag string, state *retryState) {
	state.opMu.Lock()
	defer state.opMu.Unlock()
	if !s.isActive(tag, state) {
		s.release(tag, state)
		return
	}
	status, err := s.manager.Status(ctx, tag)
	if err == nil && status.State == StateUp {
		// Keenetic rebuilds its iptables ruleset on every network event and
		// wipes rules it does not own, including the FORWARD accept that lets
		// LAN traffic into the tunnel. FORWARD policy is DROP, so losing it
		// silently breaks routed clients while the router itself keeps
		// working. Re-assert it while the transport is healthy; the helper
		// checks with -C first, so a present rule costs one cheap exec.
		if s.runtimeRuleCheckDue(tag, state, time.Now()) {
			if transport, ok := s.manager.Get(tag); ok {
				if enforcer, ok := transport.(runtimeRuleEnforcer); ok {
					if ruleErr := enforcer.EnsureRuntimeRules(); ruleErr != nil {
						log.Printf("transport %s: restore forwarding rules: %v", tag, ruleErr)
					}
				}
			}
		}
		s.recordHealthy(tag, state)
		return
	}
	if s.recordLoss(tag, state) {
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err == nil && status.State == StateDegraded {
		err = s.manager.Down(operationCtx, tag)
	}
	if err == nil {
		err = s.manager.Up(operationCtx, tag)
	}
	s.recordAttempt(tag, state, err)
}

// Keenetic can rebuild its firewall after a network event, but spawning
// iptables/ip6tables for every transport on every five-second supervisor tick
// is unnecessarily expensive. The initial zero value checks immediately;
// subsequent safety checks are coalesced to once per 30 seconds.
func (s *Supervisor) runtimeRuleCheckDue(tag string, expected *retryState, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists || state != expected || now.Before(state.nextRuleCheck) {
		return false
	}
	state.nextRuleCheck = now.Add(s.runtimeRuleInterval)
	return true
}

func (s *Supervisor) release(tag string, expected *retryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, exists := s.states[tag]; exists && state == expected {
		state.inFlight = false
	}
}

func (s *Supervisor) isActive(tag string, state *retryState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[tag] == state && state.desired
}

func (s *Supervisor) recordHealthy(tag string, expected *retryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists || state != expected {
		return
	}
	state.inFlight = false
	state.next = time.Time{}
	if !state.observedUp {
		state.observedUp = true
		state.healthySince = time.Now()
	}
	if time.Since(state.healthySince) >= s.stablePeriod {
		state.attempts = 0
	}
}

func (s *Supervisor) recordLoss(tag string, expected *retryState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists || state != expected || !state.observedUp {
		return false
	}
	state.observedUp = false
	state.healthySince = time.Time{}
	state.nextRuleCheck = time.Time{}
	s.scheduleRetry(state)
	return true
}

func (s *Supervisor) recordAttempt(tag string, expected *retryState, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists || state != expected {
		return
	}
	state.inFlight = false
	if err == nil {
		state.next = time.Time{}
		state.observedUp = true
		state.healthySince = time.Now()
		return
	}
	state.observedUp = false
	state.healthySince = time.Time{}
	s.scheduleRetry(state)
}

func (s *Supervisor) scheduleRetry(state *retryState) {
	state.inFlight = false
	state.attempts++
	backoff := s.baseBackoff
	for i := 1; i < state.attempts && backoff < s.maxBackoff; i++ {
		backoff *= 2
		if backoff > s.maxBackoff {
			backoff = s.maxBackoff
		}
	}
	state.next = time.Now().Add(backoff)
}

func (s *Supervisor) Up(ctx context.Context, tag string) error {
	status, err := s.manager.Status(ctx, tag)
	if err != nil {
		return err
	}
	if status.Type == "native" {
		return s.manager.Up(ctx, tag)
	}
	if group, state := s.groupStateForTag(tag); state != nil {
		state.opMu.Lock()
		defer state.opMu.Unlock()
		err = s.manager.Up(ctx, tag)
		s.recordGroupAttempt(group, state, err)
		return err
	}
	state := s.stateFor(tag)
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.setDesired(tag, state, true)
	err = s.manager.Up(ctx, tag)
	s.recordAttempt(tag, state, err)
	return err
}

func (s *Supervisor) Down(ctx context.Context, tag string) error {
	status, err := s.manager.Status(ctx, tag)
	if err != nil {
		return err
	}
	if status.Type == "native" {
		return s.manager.Down(ctx, tag)
	}
	if group, state := s.groupStateForTag(tag); state != nil {
		state.opMu.Lock()
		defer state.opMu.Unlock()
		err = s.manager.Down(ctx, tag)
		s.mu.Lock()
		if current := s.groupStates[group]; current == state {
			state.attempts = 0
			state.next = time.Time{}
			state.inFlight = false
			state.observedUp = state.runtime.Healthy()
			state.healthySince = time.Now()
		}
		s.mu.Unlock()
		return err
	}
	state := s.stateFor(tag)
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.setDesired(tag, state, false)
	return s.manager.Down(ctx, tag)
}

func (s *Supervisor) Restart(ctx context.Context, tag string) error {
	status, err := s.manager.Status(ctx, tag)
	if err != nil {
		return err
	}
	if status.Type == "native" {
		return s.manager.Restart(ctx, tag)
	}
	if group, state := s.groupStateForTag(tag); state != nil {
		state.opMu.Lock()
		defer state.opMu.Unlock()
		err = s.manager.Restart(ctx, tag)
		s.recordGroupAttempt(group, state, err)
		return err
	}
	state := s.stateFor(tag)
	state.opMu.Lock()
	defer state.opMu.Unlock()
	s.setDesired(tag, state, true)
	err = s.manager.Restart(ctx, tag)
	s.recordAttempt(tag, state, err)
	return err
}

func (s *Supervisor) groupStateForTag(tag string) (string, *groupRetryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.tagGroups[tag]
	return key, s.groupStates[key]
}

func (s *Supervisor) stateFor(tag string) *retryState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists {
		state = &retryState{}
		s.states[tag] = state
	}
	return state
}

func (s *Supervisor) setDesired(tag string, expected *retryState, desired bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[tag]
	if !exists || state != expected {
		return
	}
	state.desired = desired
	state.attempts = 0
	state.next = time.Time{}
	state.observedUp = false
	state.healthySince = time.Time{}
}

func (s *Supervisor) Statuses(ctx context.Context) []Status {
	statuses := s.manager.Statuses(ctx)
	for i := range statuses {
		s.decorate(&statuses[i])
	}
	return statuses
}

func (s *Supervisor) Status(ctx context.Context, tag string) (Status, error) {
	status, err := s.manager.Status(ctx, tag)
	if err != nil {
		return Status{}, err
	}
	s.decorate(&status)
	return status, nil
}

func (s *Supervisor) decorate(status *Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, grouped := s.tagGroups[status.Tag]; grouped {
		if state := s.groupStates[key]; state != nil {
			status.RetryCount = state.attempts
			if !state.next.IsZero() {
				next := state.next.UTC()
				status.NextRetryAt = &next
			}
		}
		return
	}
	state, exists := s.states[status.Tag]
	if !exists {
		return
	}
	status.DesiredUp = state.desired
	status.RetryCount = state.attempts
	if !state.next.IsZero() {
		next := state.next.UTC()
		status.NextRetryAt = &next
	}
}

func (s *Supervisor) Close(ctx context.Context) error {
	return s.manager.Close(ctx)
}

var _ interface {
	Up(context.Context, string) error
	Down(context.Context, string) error
	Restart(context.Context, string) error
	Status(context.Context, string) (Status, error)
	Statuses(context.Context) []Status
} = (*Supervisor)(nil)
