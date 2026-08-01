package transport

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFirewallCall struct {
	binary    string
	op        string
	rule      []string
	wait      bool
	waitValue string
}

type fakeFirewallRunner struct {
	mu sync.Mutex

	waitSupported      bool
	waitValueSupported bool
	commentSupported   bool
	rules              map[string]map[string]int
	scripted           map[string][]firewallCommandResult
	hooks              map[string][]func(*fakeFirewallRunner)
	calls              []fakeFirewallCall
}

func newFakeFirewallRunner() *fakeFirewallRunner {
	return &fakeFirewallRunner{
		waitSupported:      true,
		waitValueSupported: true,
		commentSupported:   true,
		rules:              map[string]map[string]int{"iptables": {}},
		scripted:           make(map[string][]firewallCommandResult),
		hooks:              make(map[string][]func(*fakeFirewallRunner)),
	}
}

func (f *fakeFirewallRunner) LookPath(binary string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.rules[binary]; !exists {
		return "", errors.New("not found")
	}
	return "/sbin/" + binary, nil
}

func (f *fakeFirewallRunner) Run(_ context.Context, binary string, args []string) firewallCommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	wait := false
	waitValue := ""
	if len(args) >= 1 && args[0] == "-w" {
		wait = true
		if !f.waitSupported {
			return firewallCommandResult{exitCode: 2, output: "iptables: unrecognized option '-w'", err: errors.New("exit status 2")}
		}
		args = args[1:]
		if len(args) > 0 && (args[0] == forwardingRuleProbeWaitSeconds || args[0] == forwardingRuleWaitSeconds) {
			waitValue = args[0]
			if !f.waitValueSupported {
				return firewallCommandResult{exitCode: 2, output: "Bad argument `" + waitValue + "'", err: errors.New("exit status 2")}
			}
			args = args[1:]
		}
	}
	if len(args) == 0 {
		return firewallCommandResult{exitCode: 2, output: "missing operation", err: errors.New("exit status 2")}
	}
	op := args[0]
	rule := append([]string(nil), args[1:]...)
	f.calls = append(f.calls, fakeFirewallCall{binary: binary, op: op, rule: rule, wait: wait, waitValue: waitValue})

	scriptKey := fakeCommandKey(binary, op, rule)
	if hooks := f.hooks[scriptKey]; len(hooks) > 0 {
		hook := hooks[0]
		f.hooks[scriptKey] = hooks[1:]
		hook(f)
	}
	if queue := f.scripted[scriptKey]; len(queue) > 0 {
		result := queue[0]
		f.scripted[scriptKey] = queue[1:]
		return result
	}

	if !f.commentSupported && slices.Contains(rule, "--comment") {
		return firewallCommandResult{
			exitCode: 2,
			output:   "iptables: Couldn't load match `comment':No such file or directory",
			err:      errors.New("exit status 2"),
		}
	}

	switch op {
	case "-C":
		if f.ruleCountLocked(binary, rule) > 0 {
			return firewallCommandResult{exitCode: 0}
		}
		return fakeAbsentResult()
	case "-A":
		f.setRuleCountLocked(binary, rule, f.ruleCountLocked(binary, rule)+1)
		return firewallCommandResult{exitCode: 0}
	case "-D":
		count := f.ruleCountLocked(binary, rule)
		if count == 0 {
			return fakeAbsentResult()
		}
		f.setRuleCountLocked(binary, rule, count-1)
		return firewallCommandResult{exitCode: 0}
	case "-S":
		return firewallCommandResult{exitCode: 0, output: f.listingLocked(binary)}
	default:
		return firewallCommandResult{exitCode: 2, output: "unsupported operation", err: errors.New("exit status 2")}
	}
}

func (f *fakeFirewallRunner) setRuleCount(binary string, rule []string, count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setRuleCountLocked(binary, rule, count)
}

func (f *fakeFirewallRunner) ruleCount(binary string, rule []string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ruleCountLocked(binary, rule)
}

func (f *fakeFirewallRunner) operationCount(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if call.op == op {
			count++
		}
	}
	return count
}

func (f *fakeFirewallRunner) commandCount(binary, op string, rule []string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if call.binary == binary && call.op == op && slices.Equal(call.rule, rule) {
			count++
		}
	}
	return count
}

func (f *fakeFirewallRunner) queue(binary, op string, rule []string, results ...firewallCommandResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fakeCommandKey(binary, op, rule)
	f.scripted[key] = append(f.scripted[key], results...)
}

func (f *fakeFirewallRunner) queueHook(binary, op string, rule []string, hooks ...func(*fakeFirewallRunner)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fakeCommandKey(binary, op, rule)
	f.hooks[key] = append(f.hooks[key], hooks...)
}

func (f *fakeFirewallRunner) setRuleCountLocked(binary string, rule []string, count int) {
	key := fakeRuleKey(rule)
	if count <= 0 {
		delete(f.rules[binary], key)
		return
	}
	f.rules[binary][key] = count
}

func (f *fakeFirewallRunner) ruleCountLocked(binary string, rule []string) int {
	return f.rules[binary][fakeRuleKey(rule)]
}

func (f *fakeFirewallRunner) listingLocked(binary string) string {
	keys := make([]string, 0, len(f.rules[binary]))
	for key := range f.rules[binary] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0)
	for _, key := range keys {
		rule := strings.Split(key, "\x00")
		for count := f.rules[binary][key]; count > 0; count-- {
			lines = append(lines, "-A "+strings.Join(rule, " "))
		}
	}
	return strings.Join(lines, "\n")
}

func fakeRuleKey(rule []string) string {
	return strings.Join(rule, "\x00")
}

func fakeCommandKey(binary, op string, rule []string) string {
	return binary + "\x00" + op + "\x00" + fakeRuleKey(rule)
}

func fakeAbsentResult() firewallCommandResult {
	return firewallCommandResult{
		exitCode: 1,
		output:   "iptables: Bad rule (does a matching rule exist in that chain?).",
		err:      errors.New("exit status 1"),
	}
}

func fakeLockResult() firewallCommandResult {
	return firewallCommandResult{
		exitCode: 4,
		output:   "Another app is currently holding the xtables lock",
		err:      errors.New("exit status 4"),
	}
}

func fakeForwardingScaffoldMissingResult() firewallCommandResult {
	return firewallCommandResult{
		exitCode: 1,
		output:   "iptables: No chain/target/match by that name.",
		err:      errors.New("exit status 1"),
	}
}

func testForwardingRuleManager(runner firewallCommandRunner) *forwardingRuleManager {
	manager := newForwardingRuleManager(runner)
	manager.sleep = func(time.Duration) {}
	manager.retryDelays = []time.Duration{0, 0, 0, 0}
	return manager
}

func TestForwardingRuleEnsureRetriesLockWithoutAppending(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	legacy := legacyForwardingRuleArgs("vless1")
	runner.setRuleCount("iptables", legacy, 1)
	runner.queue("iptables", "-C", legacy, fakeLockResult())

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", legacy); count != 1 {
		t.Fatalf("legacy rule count = %d, want 1", count)
	}
	if additions := runner.operationCount("-A"); additions != 0 {
		t.Fatalf("unexpected append after transient inspection: %d", additions)
	}
}

func TestForwardingRuleEnsureWaitsForNDMSForwardingScaffold(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	manager.scaffoldRetryDelays = []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}
	var sleeps []time.Duration
	manager.sleep = func(delay time.Duration) { sleeps = append(sleeps, delay) }
	marked := forwardingRuleArgs("vless1")
	runner.queue(
		"iptables",
		"-C",
		marked,
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)
	runner.queue(
		"iptables",
		"-S",
		[]string{"FORWARD"},
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	wantSleeps := append(append([]time.Duration(nil), manager.scaffoldRetryDelays...), manager.scaffoldStableDelay)
	if !slices.Equal(sleeps, wantSleeps) {
		t.Fatalf("scaffold retry sleeps = %v, want %v", sleeps, wantSleeps)
	}
	if got := manager.waitSupport["iptables"]; got != xtablesWaitWithTimeout {
		t.Fatalf("wait mode = %d, want numeric timeout mode %d", got, xtablesWaitWithTimeout)
	}
	if count := runner.ruleCount("iptables", marked); count != 1 {
		t.Fatalf("marked rule count = %d, want 1", count)
	}
}

func TestForwardingRuleEnsureRetriesWhenScaffoldVanishesBeforeAppend(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	manager.scaffoldRetryDelays = []time.Duration{100 * time.Millisecond}
	var sleeps []time.Duration
	manager.sleep = func(delay time.Duration) { sleeps = append(sleeps, delay) }
	marked := forwardingRuleArgs("vless1")
	runner.queue("iptables", "-S", []string{"FORWARD"}, fakeForwardingScaffoldMissingResult())
	runner.queue("iptables", "-A", marked, fakeForwardingScaffoldMissingResult())

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	wantSleeps := append(append([]time.Duration(nil), manager.scaffoldRetryDelays...), manager.scaffoldStableDelay)
	if !slices.Equal(sleeps, wantSleeps) {
		t.Fatalf("scaffold retry sleeps = %v, want %v", sleeps, wantSleeps)
	}
	if count := runner.ruleCount("iptables", marked); count != 1 {
		t.Fatalf("marked rule count = %d, want 1", count)
	}
	if count := runner.ruleCount("iptables", legacyForwardingRuleArgs("vless1")); count != 0 {
		t.Fatalf("unsafe compatibility fallback appended %d rule(s)", count)
	}
}

func TestForwardingRuleEnsureRebuildsFullPassAfterNDMSWipesEarlierFamily(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.rules["ip6tables"] = make(map[string]int)
	manager := testForwardingRuleManager(runner)
	manager.scaffoldRetryDelays = []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}
	manager.scaffoldStableDelay = 250 * time.Millisecond
	marked := forwardingRuleArgs("vless1")
	runner.queue("ip6tables", "-C", marked, fakeForwardingScaffoldMissingResult())
	runner.queue("ip6tables", "-S", []string{"FORWARD"}, fakeForwardingScaffoldMissingResult())
	runner.queueHook("ip6tables", "-A", marked, func(runner *fakeFirewallRunner) {
		runner.setRuleCountLocked("iptables", marked, 0)
	})

	var sleeps []time.Duration
	manager.sleep = func(delay time.Duration) { sleeps = append(sleeps, delay) }

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	wantSleeps := []time.Duration{
		manager.scaffoldRetryDelays[0],
		manager.scaffoldStableDelay,
		manager.scaffoldRetryDelays[1],
		manager.scaffoldStableDelay,
	}
	if !slices.Equal(sleeps, wantSleeps) {
		t.Fatalf("scaffold retry sleeps = %v, want %v", sleeps, wantSleeps)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if count := runner.ruleCount(binary, marked); count != 1 {
			t.Fatalf("%s marked rule count = %d, want 1", binary, count)
		}
	}
}

func TestForwardingRuleEnsureBoundsMissingScaffoldRetries(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	manager.scaffoldRetryDelays = []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}
	var sleeps []time.Duration
	manager.sleep = func(delay time.Duration) { sleeps = append(sleeps, delay) }
	marked := forwardingRuleArgs("vless1")
	runner.queue(
		"iptables",
		"-C",
		marked,
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)
	runner.queue(
		"iptables",
		"-S",
		[]string{"FORWARD"},
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)

	err := manager.ensureInterfaces([]string{"vless1"})
	if !errors.Is(err, errForwardingScaffoldUnavailable) {
		t.Fatalf("ensure error = %v, want missing forwarding scaffold", err)
	}
	if !slices.Equal(sleeps, manager.scaffoldRetryDelays) {
		t.Fatalf("scaffold retry sleeps = %v, want %v", sleeps, manager.scaffoldRetryDelays)
	}
	if additions := runner.operationCount("-A"); additions != 0 {
		t.Fatalf("missing scaffold appended %d rule(s)", additions)
	}
}

func TestForwardingRuleEnsureNeverAppendsAfterUncertainInspection(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	marked := forwardingRuleArgs("vless1")
	for range 5 {
		runner.queue("iptables", "-C", marked, fakeLockResult())
	}

	err := manager.ensureInterfaces([]string{"vless1"})
	if err == nil {
		t.Fatal("expected exhausted lock retry to fail")
	}
	if additions := runner.operationCount("-A"); additions != 0 {
		t.Fatalf("uncertain inspection appended %d rule(s)", additions)
	}
}

func TestForwardingRuleEnsureDoesNotTreatPermissionRC1AsAbsent(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	marked := forwardingRuleArgs("vless1")
	runner.queue("iptables", "-C", marked, firewallCommandResult{
		exitCode: 1,
		output:   "iptables: Permission denied (you must be root)",
		err:      errors.New("exit status 1"),
	})

	if err := manager.ensureInterfaces([]string{"vless1"}); err == nil {
		t.Fatal("expected permission error")
	}
	if additions := runner.operationCount("-A"); additions != 0 {
		t.Fatalf("permission failure appended %d rule(s)", additions)
	}
}

func TestForwardingRuleEnsureIsSerializedAndIdempotent(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	const workers = 32
	errorsCh := make(chan error, workers)
	var workersGroup sync.WaitGroup
	for range workers {
		workersGroup.Add(1)
		go func() {
			defer workersGroup.Done()
			errorsCh <- manager.ensureInterfaces([]string{"vless1"})
		}()
	}
	workersGroup.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if count := runner.ruleCount("iptables", forwardingRuleArgs("vless1")); count != 1 {
		t.Fatalf("marked rule count = %d, want 1", count)
	}
	if additions := runner.operationCount("-A"); additions != 1 {
		t.Fatalf("append count = %d, want 1", additions)
	}
}

func TestForwardingRuleEnsureDeduplicatesLegacyButPreservesOne(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.commentSupported = false
	manager := testForwardingRuleManager(runner)
	legacy := legacyForwardingRuleArgs("vless1")
	runner.setRuleCount("iptables", legacy, 95)

	if err := manager.ensureInterfaces([]string{"vless1", "vless1"}); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", legacy); count != 1 {
		t.Fatalf("legacy rule count = %d, want 1", count)
	}
	if additions := runner.operationCount("-A"); additions != 0 {
		t.Fatalf("legacy dedupe unexpectedly appended %d rule(s)", additions)
	}
}

func TestForwardingRuleCleanupRemovesEveryConfiguredLegacyDuplicate(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	legacy := legacyForwardingRuleArgs("vless1")
	runner.setRuleCount("iptables", legacy, 100)
	runner.queue("iptables", "-D", legacy, fakeLockResult())

	if err := manager.cleanupInterfaces([]string{"vless1", "vless1"}, true); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", legacy); count != 0 {
		t.Fatalf("legacy rule count after startup cleanup = %d, want 0", count)
	}
	if checks := runner.operationCount("-C"); checks != 0 {
		t.Fatalf("startup cleanup performed %d fragile check(s)", checks)
	}
}

func TestForwardingRuleCleanupIgnoresUnrepresentableMarkedRuleAndRemovesLegacy(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	marked := forwardingRuleArgs("vless1")
	legacy := legacyForwardingRuleArgs("vless1")
	runner.setRuleCount("iptables", legacy, 1)
	runner.queue(
		"iptables",
		"-D",
		marked,
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)

	if err := manager.cleanupInterfaces([]string{"vless1"}, true); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", legacy); count != 0 {
		t.Fatalf("compatibility rule count after cleanup = %d, want 0", count)
	}
	if manager.commentSupport["iptables"] != commentMatchUnavailable {
		t.Fatal("cleanup did not cache unavailable comment matcher")
	}
}

func TestForwardingRuleEnsureFallsBackWhenCommentMatchIsUnavailable(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.commentSupported = false
	manager := testForwardingRuleManager(runner)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", legacyForwardingRuleArgs("vless1")); count != 1 {
		t.Fatalf("compatibility rule count = %d, want 1", count)
	}
	if count := runner.ruleCount("iptables", forwardingRuleArgs("vless1")); count != 0 {
		t.Fatalf("marked rule count = %d, want 0", count)
	}
}

func TestForwardingRuleManagerSupportsBusyBoxWithoutWaitOption(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.waitSupported = false
	manager := testForwardingRuleManager(runner)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	for _, call := range runner.calls {
		if call.wait {
			t.Fatalf("command %s unexpectedly used unsupported -w", call.op)
		}
	}
}

func TestForwardingRuleManagerSupportsBusyBoxWithBareWaitFlag(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.waitValueSupported = false
	manager := testForwardingRuleManager(runner)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if got := manager.waitSupport["iptables"]; got != xtablesWaitFlagOnly {
		t.Fatalf("wait mode = %d, want bare flag mode %d", got, xtablesWaitFlagOnly)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	for _, call := range runner.calls {
		if call.wait && call.waitValue != "" {
			t.Fatalf("command %s unexpectedly used wait value %q", call.op, call.waitValue)
		}
	}
}

func TestForwardingRuleManagerUsesNumericWaitWhenSupported(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if got := manager.waitSupport["iptables"]; got != xtablesWaitWithTimeout {
		t.Fatalf("wait mode = %d, want numeric timeout mode %d", got, xtablesWaitWithTimeout)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	foundTimedOperation := false
	for _, call := range runner.calls {
		if call.op != "-S" && call.waitValue == forwardingRuleWaitSeconds {
			foundTimedOperation = true
		}
	}
	if !foundTimedOperation {
		t.Fatal("no forwarding-rule operation used the numeric xtables wait timeout")
	}
}

func TestWaitValueUnavailableMatchesOnlyTheProbedValue(t *testing.T) {
	liveError := firewallCommandResult{
		exitCode: 2,
		output:   "Bad argument `1' Try `iptables -h' or 'iptables --help' for more information.",
		err:      errors.New("exit status 2"),
	}
	if !isWaitValueUnavailable(liveError, "1") {
		t.Fatal("exact Keenetic bad wait-value error was not recognized")
	}
	if isWaitValueUnavailable(liveError, "0") {
		t.Fatal("error for wait value 1 was attributed to wait value 0")
	}
	if isWaitValueUnavailable(firewallCommandResult{exitCode: 2, output: "Bad argument `10'"}, "1") {
		t.Fatal("error for wait value 10 was attributed to wait value 1")
	}
	if isWaitValueUnavailable(firewallCommandResult{exitCode: 2, output: "Bad argument `FORWARD'"}, "1") {
		t.Fatal("unrelated bad argument was classified as unsupported wait value")
	}
}

func TestCountExactForwardingRulesDoesNotMatchSimilarInterfaceOrExtraPredicates(t *testing.T) {
	rule := legacyForwardingRuleArgs("tun1")
	listing := strings.Join([]string{
		"-A FORWARD -o tun1 -j ACCEPT",
		"-A FORWARD -o tun10 -j ACCEPT",
		"-A FORWARD -o tun1 -p tcp -j ACCEPT",
		"-A FORWARD -o tun1 -m comment --comment other -j ACCEPT",
	}, "\n")
	if count := countExactForwardingRules(listing, rule); count != 1 {
		t.Fatalf("exact rule count = %d, want 1", count)
	}
}

func TestForwardingRuleEnsureUsesCompatibilityRuleForAmbiguousKeeneticCommentFailure(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	var sleeps int
	manager.sleep = func(time.Duration) { sleeps++ }
	marked := forwardingRuleArgs("vless1")
	ambiguousFailure := firewallCommandResult{
		exitCode: 2,
		output:   "iptables: No chain/target/match by that name",
		err:      errors.New("exit status 2"),
	}
	runner.queue("iptables", "-A", marked, ambiguousFailure, ambiguousFailure)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if count := runner.ruleCount("iptables", marked); count != 0 {
		t.Fatalf("unsupported marked rule count = %d, want 0", count)
	}
	if count := runner.ruleCount("iptables", legacyForwardingRuleArgs("vless1")); count != 1 {
		t.Fatalf("compatibility rule count = %d, want 1", count)
	}
	markedChecks := runner.commandCount("iptables", "-C", marked)
	sleepsAfterDetection := sleeps
	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if got := runner.commandCount("iptables", "-C", marked); got != markedChecks {
		t.Fatalf("cached unavailable comment matcher performed %d extra marked check(s)", got-markedChecks)
	}
	if sleeps != sleepsAfterDetection {
		t.Fatalf("cached unavailable comment matcher added %d sleep(s)", sleeps-sleepsAfterDetection)
	}
}

func TestForwardingRuleEnsureRecognizesAmbiguousManagedInspectionAsUnavailableComment(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	marked := forwardingRuleArgs("vless1")
	runner.queue(
		"iptables",
		"-C",
		marked,
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if additions := runner.commandCount("iptables", "-A", marked); additions != 0 {
		t.Fatalf("unsupported marked rule appended %d time(s)", additions)
	}
	if count := runner.ruleCount("iptables", legacyForwardingRuleArgs("vless1")); count != 1 {
		t.Fatalf("compatibility rule count = %d, want 1", count)
	}
}

func TestForwardingRuleInspectionKeepsUnrelatedAmbiguousFailureFatal(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	rule := []string{"FORWARD", "-p", "tcp", "-m", "comment", "--comment", "unrelated", "-j", "ACCEPT"}
	runner.queue(
		"iptables",
		"-C",
		rule,
		fakeForwardingScaffoldMissingResult(),
		fakeForwardingScaffoldMissingResult(),
	)

	_, err := manager.rulePresentLocked("iptables", rule)
	if err == nil {
		t.Fatal("expected unrelated inspection failure")
	}
	if errors.Is(err, errCommentMatchUnavailable) || errors.Is(err, errForwardingScaffoldUnavailable) {
		t.Fatalf("unrelated inspection error was misclassified: %v", err)
	}
}

func TestForwardingRuleAppendKeepsUnrelatedAmbiguousCommentFailureFatal(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	rule := []string{"FORWARD", "-p", "tcp", "-m", "comment", "--comment", "unrelated", "-j", "ACCEPT"}
	ambiguousFailure := firewallCommandResult{
		exitCode: 2,
		output:   "iptables: No chain/target/match by that name",
		err:      errors.New("exit status 2"),
	}
	runner.queue("iptables", "-A", rule, ambiguousFailure, ambiguousFailure)

	err := manager.appendRuleLocked("iptables", rule)
	if err == nil {
		t.Fatal("expected unrelated append failure")
	}
	if errors.Is(err, errCommentMatchUnavailable) || errors.Is(err, errForwardingScaffoldUnavailable) {
		t.Fatalf("unrelated append error was misclassified: %v", err)
	}
}

func TestForwardingRuleAppendKeepsLegacyAmbiguousFailureFatal(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	legacy := legacyForwardingRuleArgs("vless1")
	ambiguousFailure := firewallCommandResult{
		exitCode: 1,
		output:   "iptables: No chain/target/match by that name",
		err:      errors.New("exit status 1"),
	}
	runner.queue("iptables", "-A", legacy, ambiguousFailure, ambiguousFailure)

	err := manager.appendRuleLocked("iptables", legacy)
	if err == nil {
		t.Fatal("expected compatibility append failure")
	}
	if errors.Is(err, errCommentMatchUnavailable) || errors.Is(err, errForwardingScaffoldUnavailable) {
		t.Fatalf("compatibility append error was misclassified: %v", err)
	}
	if attempts := runner.commandCount("iptables", "-A", legacy); attempts != 2 {
		t.Fatalf("compatibility append attempts = %d, want 2", attempts)
	}
}

func TestForwardingRuleEnsureRetriesAmbiguousAppendAfterScaffoldReturns(t *testing.T) {
	runner := newFakeFirewallRunner()
	manager := testForwardingRuleManager(runner)
	marked := forwardingRuleArgs("vless1")
	runner.queue("iptables", "-A", marked, firewallCommandResult{
		exitCode: 1,
		output:   "iptables: No chain/target/match by that name",
		err:      errors.New("exit status 1"),
	})

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if additions := runner.operationCount("-A"); additions != 2 {
		t.Fatalf("append attempts = %d, want exactly 2", additions)
	}
	if count := runner.ruleCount("iptables", marked); count != 1 {
		t.Fatalf("marked rule count = %d, want 1", count)
	}
	if count := runner.ruleCount("iptables", legacyForwardingRuleArgs("vless1")); count != 0 {
		t.Fatalf("unsafe compatibility fallback appended %d rule(s)", count)
	}
}

func TestForwardingRuleWaitCapabilityIsCachedPerBinary(t *testing.T) {
	runner := newFakeFirewallRunner()
	runner.rules["ip6tables"] = make(map[string]int)
	manager := testForwardingRuleManager(runner)

	if err := manager.ensureInterfaces([]string{"vless1"}); err != nil {
		t.Fatal(err)
	}
	if len(manager.waitSupport) != 2 {
		t.Fatalf("wait capability entries = %d, want 2", len(manager.waitSupport))
	}
}

func TestFirewallCommandErrorIncludesOperation(t *testing.T) {
	err := firewallCommandError("iptables", []string{"-C", "FORWARD"}, firewallCommandResult{exitCode: 2, output: "bad"})
	if !strings.Contains(err.Error(), "iptables -C FORWARD") {
		t.Fatalf("error lacks operation: %v", err)
	}
	if got := fmt.Sprint(err); got == "" {
		t.Fatal("empty error")
	}
}
