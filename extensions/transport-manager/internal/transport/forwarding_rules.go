package transport

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	forwardingRuleCommandTimeout   = 12 * time.Second
	forwardingRuleWaitSeconds      = "10"
	forwardingRuleProbeWaitSeconds = "1"
	forwardingScaffoldStableDelay  = 250 * time.Millisecond
	maximumForwardingRuleDeletes   = 8192
)

var forwardingRuleRetryDelays = []time.Duration{
	50 * time.Millisecond,
	100 * time.Millisecond,
	200 * time.Millisecond,
	400 * time.Millisecond,
}

// Creating a TUN interface makes NDMS rebuild its firewall on some Keenetic
// firmwares. During that rebuild the filter table can temporarily exist
// without its built-in FORWARD chain. This window is materially longer than
// an xtables lock hand-off, so keep it on a separate bounded backoff rather
// than weakening the normal command-error handling.
var forwardingScaffoldRetryDelays = []time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
}

type xtablesWaitMode uint8

const (
	xtablesWaitUnknown xtablesWaitMode = iota
	xtablesWaitWithTimeout
	xtablesWaitFlagOnly
	xtablesWaitUnavailable
)

type commentMatchMode uint8

const (
	commentMatchUnknown commentMatchMode = iota
	commentMatchAvailable
	commentMatchUnavailable
)

type firewallCommandResult struct {
	exitCode int
	output   string
	err      error
}

type firewallCommandRunner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, []string) firewallCommandResult
}

type execFirewallCommandRunner struct{}

func (execFirewallCommandRunner) LookPath(binary string) (string, error) {
	return exec.LookPath(binary)
}

func (execFirewallCommandRunner) Run(ctx context.Context, binary string, args []string) firewallCommandResult {
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	result := firewallCommandResult{output: strings.TrimSpace(string(output)), err: err, exitCode: -1}
	if err == nil {
		result.exitCode = 0
		return result
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
	}
	if ctx.Err() != nil {
		result.err = ctx.Err()
	}
	return result
}

type forwardingRuleManager struct {
	// Keenetic's NDMS and keen-pbr update the same xtables ruleset. Serialize
	// every transport-manager inspection and mutation so isolated and shared
	// sing-box runtimes cannot turn one transient lock miss into duplicate rules.
	mu sync.Mutex

	runner              firewallCommandRunner
	sleep               func(time.Duration)
	retryDelays         []time.Duration
	scaffoldRetryDelays []time.Duration
	scaffoldStableDelay time.Duration
	waitSupport         map[string]xtablesWaitMode
	commentSupport      map[string]commentMatchMode
}

var systemForwardingRules = newForwardingRuleManager(execFirewallCommandRunner{})

func newForwardingRuleManager(runner firewallCommandRunner) *forwardingRuleManager {
	return &forwardingRuleManager{
		runner:              runner,
		sleep:               time.Sleep,
		retryDelays:         append([]time.Duration(nil), forwardingRuleRetryDelays...),
		scaffoldRetryDelays: append([]time.Duration(nil), forwardingScaffoldRetryDelays...),
		scaffoldStableDelay: forwardingScaffoldStableDelay,
		waitSupport:         make(map[string]xtablesWaitMode),
		commentSupport:      make(map[string]commentMatchMode),
	}
}

func forwardingRuleArgs(interfaceName string) []string {
	return []string{"FORWARD", "-o", interfaceName, "-m", "comment", "--comment", "keen-pbr-sb:" + interfaceName, "-j", "ACCEPT"}
}

func legacyForwardingRuleArgs(interfaceName string) []string {
	return []string{"FORWARD", "-o", interfaceName, "-j", "ACCEPT"}
}

func (m *forwardingRuleManager) ensureInterfaces(interfaceNames []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	interfaces := uniqueNonEmptyStrings(interfaceNames)
	sawScaffoldTransient := false
	for attempt := 0; ; attempt++ {
		err := m.ensureInterfacesOnceLocked(interfaces)
		if err == nil && sawScaffoldTransient {
			m.sleep(m.scaffoldStableDelay)
			stable, stableErr := m.rulesPresentLocked(interfaces)
			switch {
			case stableErr != nil:
				err = stableErr
			case !stable:
				err = errForwardingRulesUnstable
			}
		}
		if err == nil {
			return nil
		}
		if !isForwardingScaffoldRetryable(err) || attempt >= len(m.scaffoldRetryDelays) {
			return err
		}
		sawScaffoldTransient = true
		m.sleep(m.scaffoldRetryDelays[attempt])
	}
}

func (m *forwardingRuleManager) ensureInterfacesOnceLocked(interfaces []string) error {
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := m.runner.LookPath(binary); err != nil {
			if binary == "iptables" {
				return fmt.Errorf("%s is required to allow LAN forwarding", binary)
			}
			continue
		}
		for _, interfaceName := range interfaces {
			if err := m.ensureInterfaceLocked(binary, interfaceName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *forwardingRuleManager) ensureInterfaceLocked(binary, interfaceName string) error {
	marked := forwardingRuleArgs(interfaceName)
	legacy := legacyForwardingRuleArgs(interfaceName)

	commentUnavailable := m.commentSupport[binary] == commentMatchUnavailable
	markedPresent := false
	var err error
	if !commentUnavailable {
		markedPresent, err = m.rulePresentLocked(binary, marked)
		commentUnavailable = errors.Is(err, errCommentMatchUnavailable)
		if commentUnavailable {
			m.commentSupport[binary] = commentMatchUnavailable
		}
		if err != nil && !commentUnavailable {
			return fmt.Errorf("inspect marked forwarding rule for %s with %s: %w", interfaceName, binary, err)
		}
	}
	if markedPresent {
		m.commentSupport[binary] = commentMatchAvailable
		if err := m.dedupeRulePreservingOneLocked(binary, marked); err != nil {
			return fmt.Errorf("deduplicate marked forwarding rule for %s with %s: %w", interfaceName, binary, err)
		}
		// A compatibility rule may have survived an older process. It is not
		// distinguishable from a user rule, so runtime reconciliation only
		// removes duplicates and deliberately preserves one matching rule.
		if err := m.dedupeRuleIfPresentLocked(binary, legacy); err != nil {
			return fmt.Errorf("deduplicate compatibility forwarding rule for %s with %s: %w", interfaceName, binary, err)
		}
		return nil
	}

	legacyPresent, err := m.rulePresentLocked(binary, legacy)
	if err != nil {
		return fmt.Errorf("inspect compatibility forwarding rule for %s with %s: %w", interfaceName, binary, err)
	}
	if legacyPresent {
		if err := m.dedupeRulePreservingOneLocked(binary, legacy); err != nil {
			return fmt.Errorf("deduplicate compatibility forwarding rule for %s with %s: %w", interfaceName, binary, err)
		}
		return nil
	}
	if commentUnavailable {
		if err := m.appendRuleLocked(binary, legacy); err != nil {
			return fmt.Errorf("allow forwarding into %s with %s compatibility rule: %w", interfaceName, binary, err)
		}
		return nil
	}

	if err := m.appendRuleLocked(binary, marked); err == nil {
		m.commentSupport[binary] = commentMatchAvailable
		return nil
	} else if !errors.Is(err, errCommentMatchUnavailable) {
		return fmt.Errorf("allow forwarding into %s with %s: %w", interfaceName, binary, err)
	}
	m.commentSupport[binary] = commentMatchUnavailable

	if err := m.appendRuleLocked(binary, legacy); err != nil {
		return fmt.Errorf("allow forwarding into %s with %s compatibility rule: %w", interfaceName, binary, err)
	}
	return nil
}

func (m *forwardingRuleManager) rulesPresent(interfaceName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	present, err := m.rulesPresentLocked([]string{interfaceName})
	return err == nil && present
}

func (m *forwardingRuleManager) rulesPresentLocked(interfaceNames []string) (bool, error) {
	interfaces := uniqueNonEmptyStrings(interfaceNames)
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := m.runner.LookPath(binary); err != nil {
			if binary == "iptables" {
				return false, fmt.Errorf("%s is required to inspect LAN forwarding", binary)
			}
			continue
		}
		for _, interfaceName := range interfaces {
			commentUnavailable := m.commentSupport[binary] == commentMatchUnavailable
			markedPresent := false
			var err error
			if !commentUnavailable {
				markedPresent, err = m.rulePresentLocked(binary, forwardingRuleArgs(interfaceName))
				commentUnavailable = errors.Is(err, errCommentMatchUnavailable)
				if commentUnavailable {
					m.commentSupport[binary] = commentMatchUnavailable
				}
				if err != nil && !commentUnavailable {
					return false, err
				}
			}
			if markedPresent {
				m.commentSupport[binary] = commentMatchAvailable
				continue
			}
			legacyPresent, err := m.rulePresentLocked(binary, legacyForwardingRuleArgs(interfaceName))
			if err != nil {
				return false, err
			}
			if !legacyPresent {
				return false, nil
			}
		}
	}
	return true, nil
}

func (m *forwardingRuleManager) cleanupInterfaces(interfaceNames []string, includeLegacy bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cleanupErrors []error
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := m.runner.LookPath(binary); err != nil {
			continue
		}
		for _, interfaceName := range uniqueNonEmptyStrings(interfaceNames) {
			rules := [][]string{forwardingRuleArgs(interfaceName)}
			if includeLegacy {
				rules = append(rules, legacyForwardingRuleArgs(interfaceName))
			}
			for _, rule := range rules {
				if err := m.removeAllRulesLocked(binary, rule); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("remove forwarding rule for %s with %s: %w", interfaceName, binary, err))
				}
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

func (m *forwardingRuleManager) rulePresentLocked(binary string, rule []string) (bool, error) {
	args := append([]string{"-C"}, rule...)
	ambiguousScaffoldRetryUsed := false
	for attempt := 0; ; attempt++ {
		result, err := m.runLocked(binary, args)
		if err != nil {
			return false, err
		}
		switch {
		case result.exitCode == 0:
			return true, nil
		case isCommentRule(rule) && isCommentMatchUnavailable(result):
			return false, fmt.Errorf("%w: %s", errCommentMatchUnavailable, commandResultDetails(result))
		case isRuleAbsent(result):
			// iptables documents exit status 1 for a rule that is not present.
			// Permission, backend and lock errors can also use status 1 and must
			// never be interpreted as permission to append.
			return false, nil
		case isXtablesTransient(result) && attempt < len(m.retryDelays):
			m.sleep(m.retryDelays[attempt])
			continue
		default:
			if isForwardingScaffoldUnavailable(result) {
				if scaffoldErr := m.confirmForwardingScaffoldLocked(binary); scaffoldErr != nil {
					return false, scaffoldErr
				}
				// NDMS can republish the filter table between the failed
				// operation and the authoritative FORWARD probe. Retry the
				// original read exactly once after the chain is visible again.
				// A repeated ambiguous failure remains fatal because it can
				// indicate a genuinely missing target or match extension.
				if !ambiguousScaffoldRetryUsed {
					ambiguousScaffoldRetryUsed = true
					m.sleep(m.scaffoldStableDelay)
					continue
				}
				if isManagedMarkedForwardingRule(rule) {
					return false, fmt.Errorf("%w: %s", errCommentMatchUnavailable, commandResultDetails(result))
				}
			}
			return false, firewallCommandError(binary, args, result)
		}
	}
}

func (m *forwardingRuleManager) appendRuleLocked(binary string, rule []string) error {
	args := append([]string{"-A"}, rule...)
	ambiguousScaffoldRetryUsed := false
	for attempt := 0; ; attempt++ {
		result, err := m.runLocked(binary, args)
		if err != nil {
			return err
		}
		if result.exitCode == 0 {
			present, inspectErr := m.rulePresentLocked(binary, rule)
			if inspectErr != nil {
				return fmt.Errorf("appended rule but could not verify it: %w", inspectErr)
			}
			if !present {
				if scaffoldErr := m.confirmForwardingScaffoldLocked(binary); scaffoldErr != nil {
					return scaffoldErr
				}
				return errors.New("iptables reported success but the appended rule is absent")
			}
			return nil
		}
		if isCommentRule(rule) && isCommentMatchUnavailable(result) {
			return fmt.Errorf("%w: %s", errCommentMatchUnavailable, commandResultDetails(result))
		}
		if isKnownNoMutationLockFailure(result) && attempt < len(m.retryDelays) {
			m.sleep(m.retryDelays[attempt])
			continue
		}
		if isForwardingScaffoldUnavailable(result) {
			if scaffoldErr := m.confirmForwardingScaffoldLocked(binary); scaffoldErr != nil {
				return scaffoldErr
			}
			// The FORWARD chain may have returned after the append raced an
			// NDMS firewall publication. One retry is safe: the first append
			// failed without mutating the table, and a second ambiguous result
			// is still treated as a permanent error with no legacy fallback.
			if !ambiguousScaffoldRetryUsed {
				ambiguousScaffoldRetryUsed = true
				m.sleep(m.scaffoldStableDelay)
				continue
			}
			if isManagedMarkedForwardingRule(rule) {
				return fmt.Errorf("%w: %s", errCommentMatchUnavailable, commandResultDetails(result))
			}
		}

		// A killed or otherwise uncertain append may have reached the kernel.
		// Verify authoritatively, but never append a second copy after an
		// uncertain outcome.
		if result.err != nil || isXtablesTransient(result) {
			present, inspectErr := m.rulePresentLocked(binary, rule)
			if inspectErr == nil && present {
				return nil
			}
			if inspectErr != nil {
				return fmt.Errorf("append outcome is uncertain and verification failed: %w", inspectErr)
			}
		}
		return firewallCommandError(binary, args, result)
	}
}

func (m *forwardingRuleManager) dedupeRuleIfPresentLocked(binary string, rule []string) error {
	present, err := m.rulePresentLocked(binary, rule)
	if err != nil || !present {
		return err
	}
	return m.dedupeRulePreservingOneLocked(binary, rule)
}

func (m *forwardingRuleManager) dedupeRulePreservingOneLocked(binary string, rule []string) error {
	count, err := m.ruleCountLocked(binary, rule)
	if err != nil {
		return err
	}
	for deleted := 0; count > 1; deleted++ {
		if deleted >= maximumForwardingRuleDeletes {
			return fmt.Errorf("refusing to delete more than %d duplicate rules", maximumForwardingRuleDeletes)
		}
		result, runErr := m.deleteRuleLocked(binary, rule)
		if runErr != nil {
			return runErr
		}
		if result.exitCode != 0 && !isRuleAbsent(result) {
			return firewallCommandError(binary, append([]string{"-D"}, rule...), result)
		}
		// Re-list before every subsequent deletion. External firewall owners
		// may mutate FORWARD concurrently; never delete the sole remaining rule.
		count, err = m.ruleCountLocked(binary, rule)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *forwardingRuleManager) removeAllRulesLocked(binary string, rule []string) error {
	if isManagedMarkedForwardingRule(rule) && m.commentSupport[binary] == commentMatchUnavailable {
		return nil
	}
	for deleted := 0; deleted < maximumForwardingRuleDeletes; deleted++ {
		result, err := m.deleteRuleLocked(binary, rule)
		if err != nil {
			if isManagedMarkedForwardingRule(rule) && errors.Is(err, errCommentMatchUnavailable) {
				m.commentSupport[binary] = commentMatchUnavailable
				return nil
			}
			return err
		}
		if result.exitCode == 0 {
			continue
		}
		if isRuleAbsent(result) {
			return nil
		}
		return firewallCommandError(binary, append([]string{"-D"}, rule...), result)
	}
	return fmt.Errorf("refusing to delete more than %d matching rules", maximumForwardingRuleDeletes)
}

func (m *forwardingRuleManager) deleteRuleLocked(binary string, rule []string) (firewallCommandResult, error) {
	args := append([]string{"-D"}, rule...)
	ambiguousScaffoldRetryUsed := false
	for attempt := 0; ; attempt++ {
		result, err := m.runLocked(binary, args)
		if err != nil {
			return result, err
		}
		if result.exitCode == 0 || isRuleAbsent(result) {
			return result, nil
		}
		if isKnownNoMutationLockFailure(result) && attempt < len(m.retryDelays) {
			m.sleep(m.retryDelays[attempt])
			continue
		}
		if isForwardingScaffoldUnavailable(result) {
			if scaffoldErr := m.confirmForwardingScaffoldLocked(binary); scaffoldErr != nil {
				return result, scaffoldErr
			}
			if !ambiguousScaffoldRetryUsed {
				ambiguousScaffoldRetryUsed = true
				m.sleep(m.scaffoldStableDelay)
				continue
			}
			if isManagedMarkedForwardingRule(rule) {
				return result, fmt.Errorf("%w: %s", errCommentMatchUnavailable, commandResultDetails(result))
			}
		}
		return result, firewallCommandError(binary, args, result)
	}
}

func (m *forwardingRuleManager) ruleCountLocked(binary string, rule []string) (int, error) {
	args := []string{"-S", "FORWARD"}
	for attempt := 0; ; attempt++ {
		result, err := m.runLocked(binary, args)
		if err != nil {
			return 0, err
		}
		if result.exitCode == 0 {
			return countExactForwardingRules(result.output, rule), nil
		}
		if isForwardingScaffoldUnavailable(result) {
			return 0, forwardingScaffoldError(binary, result)
		}
		if isXtablesTransient(result) && attempt < len(m.retryDelays) {
			m.sleep(m.retryDelays[attempt])
			continue
		}
		return 0, firewallCommandError(binary, args, result)
	}
}

// confirmForwardingScaffoldLocked authoritatively distinguishes a missing
// FORWARD chain from the deliberately ambiguous "No chain/target/match"
// error returned by append operations. A successful probe keeps arbitrary
// rule failures fatal. Only the exact managed forwarding rule may separately
// classify a repeated failure as Keenetic's unavailable comment matcher and
// use the existing unmarked compatibility rule.
func (m *forwardingRuleManager) confirmForwardingScaffoldLocked(binary string) error {
	args := []string{"-S", "FORWARD"}
	for attempt := 0; ; attempt++ {
		result, err := m.runLocked(binary, args)
		if err != nil {
			return err
		}
		if result.exitCode == 0 {
			return nil
		}
		if isForwardingScaffoldUnavailable(result) {
			return forwardingScaffoldError(binary, result)
		}
		if isXtablesTransient(result) && attempt < len(m.retryDelays) {
			m.sleep(m.retryDelays[attempt])
			continue
		}
		return firewallCommandError(binary, args, result)
	}
}

func (m *forwardingRuleManager) runLocked(binary string, args []string) (firewallCommandResult, error) {
	waitSupport, err := m.waitSupportLocked(binary)
	if err != nil {
		return firewallCommandResult{}, err
	}
	commandArgs := append([]string(nil), args...)
	switch waitSupport {
	case xtablesWaitWithTimeout:
		commandArgs = append([]string{"-w", forwardingRuleWaitSeconds}, commandArgs...)
	case xtablesWaitFlagOnly:
		commandArgs = append([]string{"-w"}, commandArgs...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), forwardingRuleCommandTimeout)
	defer cancel()
	return m.runner.Run(ctx, binary, commandArgs), nil
}

func (m *forwardingRuleManager) waitSupportLocked(binary string) (xtablesWaitMode, error) {
	if support := m.waitSupport[binary]; support != xtablesWaitUnknown {
		return support, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), forwardingRuleCommandTimeout)
	defer cancel()
	// Probe xtables wait syntax with a chainless listing. FORWARD can
	// temporarily disappear while NDMS republishes the filter table, and that
	// runtime state must not be confused with the binary's wait capability.
	result := m.runner.Run(ctx, binary, []string{"-w", forwardingRuleProbeWaitSeconds, "-S"})
	if result.exitCode == 0 || isKnownNoMutationLockFailure(result) {
		m.waitSupport[binary] = xtablesWaitWithTimeout
		return xtablesWaitWithTimeout, nil
	}
	if isWaitValueUnavailable(result, forwardingRuleProbeWaitSeconds) {
		bareCtx, bareCancel := context.WithTimeout(context.Background(), forwardingRuleCommandTimeout)
		defer bareCancel()
		bareResult := m.runner.Run(bareCtx, binary, []string{"-w", "-S"})
		if bareResult.exitCode == 0 || isKnownNoMutationLockFailure(bareResult) {
			m.waitSupport[binary] = xtablesWaitFlagOnly
			return xtablesWaitFlagOnly, nil
		}
		if isWaitOptionUnavailable(bareResult) {
			m.waitSupport[binary] = xtablesWaitUnavailable
			return xtablesWaitUnavailable, nil
		}
		return xtablesWaitUnknown, fmt.Errorf("probe %s bare xtables wait support: %w", binary, firewallCommandError(binary, []string{"-w", "-S"}, bareResult))
	}
	if isWaitOptionUnavailable(result) {
		m.waitSupport[binary] = xtablesWaitUnavailable
		return xtablesWaitUnavailable, nil
	}
	return xtablesWaitUnknown, fmt.Errorf("probe %s xtables wait support: %w", binary, firewallCommandError(binary, []string{"-w", forwardingRuleProbeWaitSeconds, "-S"}, result))
}

func isWaitValueUnavailable(result firewallCommandResult, attemptedValue string) bool {
	text := strings.ToLower(result.output)
	if !(strings.Contains(text, "bad argument") ||
		strings.Contains(text, "invalid argument") ||
		strings.Contains(text, "invalid wait")) {
		return false
	}
	for _, field := range strings.Fields(text) {
		if strings.Trim(field, "`'\".,:;()[]") == attemptedValue {
			return true
		}
	}
	return false
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func countExactForwardingRules(listing string, rule []string) int {
	expected := append([]string{"-A"}, rule...)
	count := 0
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != len(expected) {
			continue
		}
		matches := true
		for index := range fields {
			if strings.Trim(fields[index], "'\"") != expected[index] {
				matches = false
				break
			}
		}
		if matches {
			count++
		}
	}
	return count
}

var (
	errCommentMatchUnavailable       = errors.New("xt_comment is unavailable")
	errForwardingScaffoldUnavailable = errors.New("iptables FORWARD scaffold is unavailable")
	errForwardingRulesUnstable       = errors.New("iptables forwarding rules changed during NDMS firewall publication")
)

func isForwardingScaffoldRetryable(err error) bool {
	return errors.Is(err, errForwardingScaffoldUnavailable) || errors.Is(err, errForwardingRulesUnstable)
}

func isForwardingScaffoldUnavailable(result firewallCommandResult) bool {
	text := strings.ToLower(strings.TrimSpace(result.output))
	return strings.Contains(text, "no chain/target/match by that name") ||
		strings.Contains(text, "no chain by that name") ||
		(strings.Contains(text, "chain") && strings.Contains(text, "forward") && strings.Contains(text, "does not exist")) ||
		strings.Contains(text, "bad rule (does a matching rule exist in that chain?)")
}

func forwardingScaffoldError(binary string, result firewallCommandResult) error {
	return fmt.Errorf("%w for %s: %s", errForwardingScaffoldUnavailable, binary, commandResultDetails(result))
}

func isCommentRule(rule []string) bool {
	for _, argument := range rule {
		if argument == "--comment" {
			return true
		}
	}
	return false
}

func isManagedMarkedForwardingRule(rule []string) bool {
	if len(rule) != 9 {
		return false
	}
	interfaceName := rule[2]
	return interfaceName != "" &&
		rule[0] == "FORWARD" &&
		rule[1] == "-o" &&
		rule[3] == "-m" &&
		rule[4] == "comment" &&
		rule[5] == "--comment" &&
		rule[6] == "keen-pbr-sb:"+interfaceName &&
		rule[7] == "-j" &&
		rule[8] == "ACCEPT"
}

func isCommentMatchUnavailable(result firewallCommandResult) bool {
	text := strings.ToLower(result.output)
	return strings.Contains(text, "couldn't load match `comment'") ||
		strings.Contains(text, "couldn't load match 'comment'") ||
		strings.Contains(text, "couldn't load match \"comment\"") ||
		strings.Contains(text, "unknown option --comment") ||
		strings.Contains(text, "unknown option `--comment'") ||
		strings.Contains(text, "comment match not found")
}

func isWaitOptionUnavailable(result firewallCommandResult) bool {
	text := strings.ToLower(result.output)
	if !strings.Contains(text, "-w") && !strings.Contains(text, "wait") {
		return false
	}
	return strings.Contains(text, "unknown option") ||
		strings.Contains(text, "unrecognized option") ||
		strings.Contains(text, "invalid option") ||
		strings.Contains(text, "illegal option") ||
		strings.Contains(text, "not supported")
}

func isKnownNoMutationLockFailure(result firewallCommandResult) bool {
	return result.exitCode == 4 || containsXtablesLockMessage(result.output)
}

func isXtablesTransient(result firewallCommandResult) bool {
	if isKnownNoMutationLockFailure(result) {
		return true
	}
	text := strings.ToLower(result.output)
	if strings.Contains(text, "resource temporarily unavailable") ||
		strings.Contains(text, "temporarily unavailable") ||
		strings.Contains(text, "device or resource busy") {
		return true
	}
	return result.err != nil && (errors.Is(result.err, context.DeadlineExceeded) || errors.Is(result.err, context.Canceled))
}

func isRuleAbsent(result firewallCommandResult) bool {
	if result.exitCode != 1 || isXtablesTransient(result) {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(result.output))
	return text == "" ||
		strings.Contains(text, "bad rule (does a matching rule exist") ||
		strings.Contains(text, "no matching rule") ||
		strings.Contains(text, "rule does not exist")
}

func containsXtablesLockMessage(output string) bool {
	text := strings.ToLower(output)
	return strings.Contains(text, "xtables lock") ||
		strings.Contains(text, "holding the xtables lock") ||
		strings.Contains(text, "another app is currently holding")
}

func commandResultDetails(result firewallCommandResult) string {
	parts := make([]string, 0, 3)
	if result.exitCode >= 0 {
		parts = append(parts, fmt.Sprintf("exit status %d", result.exitCode))
	}
	if result.err != nil {
		parts = append(parts, result.err.Error())
	}
	if result.output != "" {
		parts = append(parts, result.output)
	}
	if len(parts) == 0 {
		return "unknown command failure"
	}
	return strings.Join(parts, ": ")
}

func firewallCommandError(binary string, args []string, result firewallCommandResult) error {
	return fmt.Errorf("%s %s: %s", binary, strings.Join(args, " "), commandResultDetails(result))
}
