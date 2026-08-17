package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	validTag       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
	validInterface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	validCountry   = regexp.MustCompile(`^[A-Za-z]{2}$`)
)

func storeRoutingHealthSnapshot(cacheKey string, values map[string]routingHealthResult) {
	routingHealthCacheMu.Lock()
	defer routingHealthCacheMu.Unlock()
	// A configured daemon normally has one endpoint. Bound the cache anyway so
	// repeated configuration changes cannot grow a process-lifetime map.
	if len(routingHealthCache) >= 8 {
		clear(routingHealthCache)
	}
	routingHealthCache[cacheKey] = routingHealthSnapshot{fetchedAt: time.Now(), values: values}
}

type TransportSpec struct {
	Tag          string     `json:"tag"`
	DisplayName  string     `json:"display_name,omitempty"`
	Type         string     `json:"type"`
	Interface    string     `json:"interface"`
	AutoStart    bool       `json:"auto_start,omitempty"`
	Link         string     `json:"link,omitempty"`
	OutboundJSON string     `json:"outbound_json,omitempty"`
	MTU          uint32     `json:"mtu,omitempty"`
	BootstrapDNS []string   `json:"bootstrap_dns,omitempty"`
	TunAddress   string     `json:"tun_address,omitempty"`
	GeoMode      string     `json:"geo_mode,omitempty"`
	CountryCode  string     `json:"country_code,omitempty"`
	Country      string     `json:"country,omitempty"`
	VLESS        *VLESSSpec `json:"vless,omitempty"` // Legacy configuration compatibility.
	// Set only on the loopback manager's redacted output, never accepted on
	// input and never stored. It is internal sensitive identity metadata: the
	// public API strips it before replying to a browser.
	LinkFingerprint string `json:"link_fingerprint,omitempty"`
}

// LinkFingerprint identifies a share link without returning the link itself.
// It is not public-safe: for low-entropy passwords this digest is an offline
// verifier and therefore stays inside the daemon-manager trust boundary.
//
// Redacted state blanks Link because it carries the credential - a VLESS UUID,
// a Trojan password. That leaves a caller unable to answer the one question a
// subscription import has to ask: is this entry already configured here? The
// digest answers it without returning the raw link. It still verifies guesses,
// which is why it must never cross the internal daemon-manager boundary.
//
// The fragment is removed first, and that is a contract, not a detail: a
// fragment is the provider's label, and the same connection listed twice under
// two names is one connection. The subscription importer on the C++ side
// derives its own identity by the same rule, so a change to either half breaks
// the comparison silently - both sides pin it in tests.
// The trimmed set is written out rather than delegated to strings.TrimSpace.
// TrimSpace removes Unicode whitespace (U+00A0, U+2028, the U+2000 block and
// more); the C++ half trims " \t\r\n\f\v". Delegating to each language's idea
// of "space" made the two halves disagree on any link that ends in one of
// those characters and carries no fragment - and the disagreement is silent,
// because a fingerprint that does not match simply reports "not configured
// yet" and offers a duplicate import. Both sides now name the same six bytes.
const linkFingerprintTrimCutset = " \t\r\n\f\v"

func LinkFingerprint(link string) string {
	trimmed := strings.Trim(link, linkFingerprintTrimCutset)
	if trimmed == "" {
		return ""
	}
	if hash := strings.IndexByte(trimmed, '#'); hash >= 0 {
		trimmed = trimmed[:hash]
	}
	if trimmed == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(digest[:])
}

type VLESSSpec struct {
	Server      string `json:"server"`
	ServerPort  uint16 `json:"server_port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow,omitempty"`
	ServerName  string `json:"server_name"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	MTU         uint32 `json:"mtu,omitempty"`
}

type SingBox struct {
	opMu                sync.Mutex
	mu                  sync.Mutex
	spec                TransportSpec
	binary, runtimeDir  string
	cmd                 *exec.Cmd
	done                chan error
	state               State
	lastErr             string
	updated             time.Time
	healthEndpoint      RoutingHealthEndpoint
	healthFailures      int
	server              string
	serverPort          int
	protocol            string
	security            string
	sni                 string
	path                TransportPath
	network             string
	interfaceByName     func(string) (*net.Interface, error)
	runtimeRulesPresent func(string) bool
}

type RoutingHealthEndpoint struct {
	URL    string
	APIKey string
}

type routingHealthResult struct {
	verdict string
	detail  string
}

type routingHealthSnapshot struct {
	fetchedAt time.Time
	values    map[string]routingHealthResult
}

var (
	routingHealthCacheMu sync.Mutex
	routingHealthCache   = make(map[string]routingHealthSnapshot)
	routingHealthClient  = &http.Client{Timeout: 2 * time.Second}
)

func NewSingBox(spec TransportSpec, binary, runtimeDir string, health ...RoutingHealthEndpoint) (*SingBox, error) {
	if !validTag.MatchString(spec.Tag) || !validInterface.MatchString(spec.Interface) {
		return nil, fmt.Errorf("tag and interface are required")
	}
	outbound, err := outboundFromSpec(spec)
	if err != nil {
		return nil, err
	}
	if _, err := tunAddressForSpec(spec); err != nil {
		return nil, err
	}
	result := &SingBox{
		spec: spec, binary: binary, runtimeDir: runtimeDir,
		state: StateDown, updated: time.Now().UTC(),
		interfaceByName:     net.InterfaceByName,
		runtimeRulesPresent: forwardingRulesPresent,
	}
	if server, ok := outbound["server"].(string); ok {
		result.server = server
	}
	if protocol, ok := outbound["type"].(string); ok {
		result.protocol = protocol
	}
	summary := summariseOutbound(outbound)
	result.serverPort = summary.port
	result.security = summary.security
	result.sni = summary.sni
	result.path = summary.path
	result.network = summary.legacyNetwork
	if len(health) > 0 {
		result.healthEndpoint = health[0]
	}
	return result, nil
}

func NewFromSpec(spec TransportSpec, binary, runtimeDir string, health ...RoutingHealthEndpoint) (Transport, error) {
	if err := ValidateTransportSpec(spec); err != nil {
		return nil, err
	}
	switch spec.Type {
	case "native":
		return NewNative(spec.Tag, spec.Interface), nil
	case "sing-box", "sing-box-vless-reality":
		return NewSingBox(spec, binary, runtimeDir, health...)
	default:
		return nil, fmt.Errorf("unsupported type %q", spec.Type)
	}
}

// ValidateTransportSpec is the common validation boundary for isolated,
// shared and native transport construction. Shared mode must not silently
// accept metadata that the default isolated mode rejects.
func ValidateTransportSpec(spec TransportSpec) error {
	if !validTag.MatchString(spec.Tag) || !validInterface.MatchString(spec.Interface) {
		return fmt.Errorf("invalid tag or interface")
	}
	// Output only. Accepting it would let a caller claim an identity for a
	// link it does not have, and a stored value would go stale the moment the
	// link changed - the redacted view derives it fresh every time.
	if spec.LinkFingerprint != "" {
		return fmt.Errorf("link_fingerprint is derived and cannot be supplied")
	}
	if err := ValidateDisplayName(spec.DisplayName); err != nil {
		return err
	}
	if err := validateGeoSpec(spec); err != nil {
		return err
	}
	switch spec.Type {
	case "native", "sing-box", "sing-box-vless-reality":
		return nil
	default:
		return fmt.Errorf("unsupported type %q", spec.Type)
	}
}

// ValidateIsolatedSingBoxInventory checks every managed transport in the exact
// configuration shape used by isolated mode. It is used before staging a mode
// switch so a restart cannot discover an incompatible config only after the
// previous shared runtime has already been stopped.
func ValidateIsolatedSingBoxInventory(
	ctx context.Context,
	specs []TransportSpec,
	binary string,
	runtimeDir string,
	health ...RoutingHealthEndpoint,
) error {
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return err
	}
	for _, spec := range specs {
		if !isManagedSingBoxSpec(spec) {
			continue
		}
		managed, err := NewSingBox(spec, binary, runtimeDir, health...)
		if err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		config, err := managed.buildConfig()
		if err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("transport %q: encode sing-box config: %w", spec.Tag, err)
		}
		file, err := os.CreateTemp(runtimeDir, ".isolated-check-*.json")
		if err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		path := file.Name()
		if chmodErr := file.Chmod(0600); chmodErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("transport %q: %w", spec.Tag, chmodErr)
		}
		if _, writeErr := file.Write(data); writeErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("transport %q: %w", spec.Tag, writeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("transport %q: %w", spec.Tag, closeErr)
		}
		command := exec.CommandContext(ctx, binary, "check", "-c", path)
		output, checkErr := command.CombinedOutput()
		_ = os.Remove(path)
		if checkErr != nil {
			return fmt.Errorf(
				"transport %q: sing-box config check: %w: %s",
				spec.Tag,
				checkErr,
				string(output),
			)
		}
	}
	return nil
}

func ValidateDisplayName(value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("display_name must be valid UTF-8")
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("display_name must contain a non-whitespace character")
	}
	if utf8.RuneCountInString(value) > 80 {
		return fmt.Errorf("display_name must be at most 80 Unicode code points")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("display_name must not contain control characters")
		}
		if isBidirectionalControl(character) {
			return fmt.Errorf("display_name must not contain bidirectional control characters")
		}
	}
	return nil
}

func isBidirectionalControl(character rune) bool {
	return character == '\u061c' ||
		character == '\u200e' ||
		character == '\u200f' ||
		(character >= '\u202a' && character <= '\u202e') ||
		(character >= '\u2066' && character <= '\u2069')
}

// RuntimeEquivalent reports whether only presentation metadata changed.
// Such an update is persisted without taking a healthy tunnel down.
func RuntimeEquivalent(left, right TransportSpec) bool {
	left.DisplayName, right.DisplayName = "", ""
	left.GeoMode, right.GeoMode = "", ""
	left.CountryCode, right.CountryCode = "", ""
	left.Country, right.Country = "", ""
	return reflect.DeepEqual(left, right)
}

func validateGeoSpec(spec TransportSpec) error {
	switch spec.GeoMode {
	case "", "disabled", "auto":
		return nil
	case "manual":
		if !validCountry.MatchString(spec.CountryCode) {
			return fmt.Errorf("manual country requires a two-letter ISO country_code")
		}
		if len([]rune(spec.Country)) > 64 {
			return fmt.Errorf("country must be at most 64 characters")
		}
		return nil
	default:
		return fmt.Errorf("unsupported geo_mode %q", spec.GeoMode)
	}
}

func (s *SingBox) Tag() string { return s.spec.Tag }

func (s *SingBox) Up(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.cmd != nil && s.cmd.Process != nil {
		s.mu.Unlock()
		return nil
	}
	s.state, s.updated, s.lastErr = StateStarting, time.Now().UTC(), ""
	s.mu.Unlock()

	if err := os.MkdirAll(s.runtimeDir, 0700); err != nil {
		return s.fail(err)
	}
	configPath := filepath.Join(s.runtimeDir, s.spec.Tag+".json")
	config, err := s.buildConfig()
	if err != nil {
		return s.fail(err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return s.fail(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return s.fail(err)
	}
	check := exec.CommandContext(ctx, s.binary, "check", "-c", configPath)
	if output, err := check.CombinedOutput(); err != nil {
		return s.fail(fmt.Errorf("sing-box config check: %w: %s", err, string(output)))
	}
	cmd := exec.CommandContext(context.Background(), s.binary, "run", "-c", configPath)
	logPath := filepath.Join(s.runtimeDir, s.spec.Tag+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return s.fail(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return s.fail(err)
	}
	s.mu.Lock()
	s.cmd, s.done = cmd, make(chan error, 1)
	done := s.done
	s.mu.Unlock()
	go s.wait(cmd, logFile)

	deadline := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop(cmd, done)
			return s.fail(ctx.Err())
		case <-deadline.C:
			s.stop(cmd, done)
			return s.fail(fmt.Errorf("interface %s did not appear", s.spec.Interface))
		case err := <-done:
			if err == nil {
				err = errors.New("sing-box exited before the interface appeared")
			}
			return s.fail(err)
		case <-ticker.C:
			if _, err := net.InterfaceByName(s.spec.Interface); err == nil {
				if err := s.ensureForwardingRules(); err != nil {
					s.stop(cmd, done)
					return s.fail(err)
				}
				s.mu.Lock()
				s.state, s.updated = StateUp, time.Now().UTC()
				s.mu.Unlock()
				return nil
			}
		}
	}
}

func (s *SingBox) fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.lastErr, s.updated = StateDegraded, err.Error(), time.Now().UTC()
	return err
}

func (s *SingBox) stop(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
	}
}

func (s *SingBox) wait(cmd *exec.Cmd, logFile *os.File) {
	err := cmd.Wait()
	_ = logFile.Close()
	s.removeForwardingRules()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != cmd {
		return
	}
	if s.done != nil {
		s.done <- err
		close(s.done)
	}
	s.cmd = nil
	s.state = StateDown
	s.updated = time.Now().UTC()
	if err != nil {
		s.lastErr = err.Error()
	}
}

func (s *SingBox) ensureForwardingRules() error {
	return systemForwardingRules.ensureInterfaces([]string{s.spec.Interface})
}

// EnsureRuntimeRules re-applies the firewall state this transport owns. Safe to
// call repeatedly: each rule is checked before it is added.
func (s *SingBox) EnsureRuntimeRules() error {
	s.mu.Lock()
	running := s.cmd != nil && s.cmd.Process != nil
	s.mu.Unlock()
	if !running {
		return nil
	}
	if err := s.ensureForwardingRules(); err != nil {
		return err
	}
	s.truncateRuntimeLog()
	return nil
}

func (s *SingBox) truncateRuntimeLog() {
	truncateRuntimeLogFile(filepath.Join(s.runtimeDir, s.spec.Tag+".log"))
}

func truncateRuntimeLogFile(path string) {
	const maximumLogBytes = 2 * 1024 * 1024
	if info, err := os.Stat(path); err == nil && info.Size() > maximumLogBytes {
		_ = os.Truncate(path, 0)
	}
}

func (s *SingBox) removeForwardingRules() {
	removeForwardingRules(s.spec.Interface, true)
}

func forwardingRulesPresent(interfaceName string) bool {
	return systemForwardingRules.rulesPresent(interfaceName)
}

func removeForwardingRules(interfaceName string, includeLegacy bool) {
	_ = systemForwardingRules.cleanupInterfaces([]string{interfaceName}, includeLegacy)
}

// CleanupForwardingRules removes rules left behind by an unclean manager exit.
// Only interfaces belonging to configured sing-box transports are touched.
func CleanupForwardingRules(specs []TransportSpec) error {
	interfaces := make([]string, 0, len(specs))
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			interfaces = append(interfaces, spec.Interface)
		}
	}
	return systemForwardingRules.cleanupInterfaces(interfaces, true)
}

// CleanupOrphanProcesses terminates sing-box children that survived an
// unclean transport-manager exit. Matching is restricted to the exact config
// paths owned by configured transports in our runtime directory.
func CleanupOrphanProcesses(specs []TransportSpec, runtimeDir string) error {
	return CleanupOrphanProcessesForMode(specs, runtimeDir, false)
}

// CleanupOrphanProcessesForMode also owns shared.json when shared mode is
// configured with an empty inventory. This closes the crash-recovery edge case
// without broad process-name matching that could kill an unrelated sing-box.
func CleanupOrphanProcessesForMode(
	specs []TransportSpec,
	runtimeDir string,
	sharedMode bool,
) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	ownedConfigs := ownedSingBoxConfigPaths(specs, runtimeDir, sharedMode)
	if len(ownedConfigs) == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("inspect /proc for orphan sing-box processes: %w", err)
	}
	var errs []error
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || !matchesOwnedSingBoxCommand(cmdline, ownedConfigs) {
			continue
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("find orphan sing-box pid %d: %w", pid, err))
			continue
		}
		if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			errs = append(errs, fmt.Errorf("kill orphan sing-box pid %d: %w", pid, err))
			continue
		}
		if !waitForOwnedProcessExit(pid, ownedConfigs, 2*time.Second) {
			errs = append(
				errs,
				fmt.Errorf("orphan sing-box pid %d did not exit after kill", pid),
			)
		}
	}
	return errors.Join(errs...)
}

func ownedSingBoxConfigPaths(
	specs []TransportSpec,
	runtimeDir string,
	sharedMode bool,
) map[string]bool {
	ownedConfigs := make(map[string]bool)
	hasManaged := false
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			hasManaged = true
			ownedConfigs[filepath.Join(runtimeDir, spec.Tag+".json")] = true
		}
	}
	if hasManaged || sharedMode {
		ownedConfigs[filepath.Join(runtimeDir, "shared.json")] = true
	}
	return ownedConfigs
}

func waitForOwnedProcessExit(pid int, ownedConfigs map[string]bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	path := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	for {
		cmdline, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return true
		}
		if err == nil && !matchesOwnedSingBoxCommand(cmdline, ownedConfigs) {
			// The PID disappeared or was reused by an unrelated process.
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func matchesOwnedSingBoxCommand(cmdline []byte, ownedConfigs map[string]bool) bool {
	parts := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	for executable := 0; executable+1 < len(parts); executable++ {
		base := filepath.Base(parts[executable])
		if (base != "sing-box" && base != "sing-box.real") || parts[executable+1] != "run" {
			continue
		}
		for index := executable + 2; index+1 < len(parts); index++ {
			if (parts[index] == "-c" || parts[index] == "--config") && ownedConfigs[parts[index+1]] {
				return true
			}
		}
	}
	return false
}

func (s *SingBox) Down(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	cmd := s.cmd
	if cmd == nil || cmd.Process == nil {
		s.state, s.updated = StateDown, time.Now().UTC()
		s.mu.Unlock()
		return nil
	}
	done := s.done
	s.mu.Unlock()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return ctx.Err()
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	case <-done:
	}
	s.mu.Lock()
	s.state, s.updated = StateDown, time.Now().UTC()
	s.mu.Unlock()
	return nil
}

func (s *SingBox) Status(ctx context.Context) Status {
	s.mu.Lock()
	pid := 0
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}
	state := s.state
	if state == StateUp {
		if _, err := net.InterfaceByName(s.spec.Interface); err != nil {
			state = StateDegraded
		}
	}
	status := Status{Tag: s.spec.Tag, DisplayName: s.spec.DisplayName, Type: s.spec.Type, Interface: s.spec.Interface, Server: s.server,
		ServerPort: s.serverPort, Protocol: s.protocol, Security: s.security, SNI: s.sni, Path: s.path, Network: s.network,
		State: state, PID: pid, Error: s.lastErr, UpdatedAt: s.updated}
	s.mu.Unlock()
	if state == StateUp {
		s.applyRoutingHealth(ctx, &status)
	}
	return status
}

// LocalRuntimeReady intentionally bypasses Status because Status also applies
// external keen-pbr routing health. A mode switch only needs proof that its
// local process, TUN device and owned forwarding rules are live.
func (s *SingBox) LocalRuntimeReady() bool {
	s.mu.Lock()
	state := s.state
	cmd := s.cmd
	interfaceByName := s.interfaceByName
	rulesPresent := s.runtimeRulesPresent
	interfaceName := s.spec.Interface
	s.mu.Unlock()
	if state != StateUp || cmd == nil || cmd.Process == nil ||
		interfaceByName == nil || rulesPresent == nil {
		return false
	}
	if _, err := interfaceByName(interfaceName); err != nil {
		return false
	}
	return rulesPresent(interfaceName)
}

func (s *SingBox) applyRoutingHealth(ctx context.Context, status *Status) {
	verdict, detail, known := s.routingHealth(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !known || verdict == "healthy" || verdict == "active" || verdict == "backup" {
		s.healthFailures = 0
		return
	}
	s.healthFailures++
	if s.healthFailures < 3 {
		return
	}
	status.State = StateDegraded
	status.Error = "keen-pbr routing health: " + verdict
	if detail != "" {
		status.Error += ": " + detail
	}
}

func (s *SingBox) routingHealth(ctx context.Context) (string, string, bool) {
	if s.healthEndpoint.URL == "" {
		return "", "", false
	}
	cacheKey := s.healthEndpoint.URL + "\x00" + s.healthEndpoint.APIKey
	routingHealthCacheMu.Lock()
	cached, found := routingHealthCache[cacheKey]
	routingHealthCacheMu.Unlock()
	if found && time.Since(cached.fetchedAt) < 2*time.Second {
		result, known := cached.values[s.spec.Interface]
		return result.verdict, result.detail, known && result.verdict != "" && result.verdict != "unknown"
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.healthEndpoint.URL, nil)
	if err != nil {
		storeRoutingHealthSnapshot(cacheKey, map[string]routingHealthResult{})
		return "", "", false
	}
	if s.healthEndpoint.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+s.healthEndpoint.APIKey)
	}
	response, err := routingHealthClient.Do(request)
	if err != nil {
		storeRoutingHealthSnapshot(cacheKey, map[string]routingHealthResult{})
		return "", "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		storeRoutingHealthSnapshot(cacheKey, map[string]routingHealthResult{})
		return "", "", false
	}
	var body struct {
		Outbounds []struct {
			Interfaces []struct {
				InterfaceName string `json:"interface_name"`
				Status        string `json:"status"`
				Detail        string `json:"detail"`
			} `json:"interfaces"`
		} `json:"outbounds"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		storeRoutingHealthSnapshot(cacheKey, map[string]routingHealthResult{})
		return "", "", false
	}
	values := make(map[string]routingHealthResult)
	for _, outbound := range body.Outbounds {
		for _, candidate := range outbound.Interfaces {
			if candidate.InterfaceName == "" {
				continue
			}
			current := values[candidate.InterfaceName]
			if current.verdict == "active" || current.verdict == "backup" {
				continue
			}
			values[candidate.InterfaceName] = routingHealthResult{
				verdict: candidate.Status,
				detail:  candidate.Detail,
			}
		}
	}
	storeRoutingHealthSnapshot(cacheKey, values)
	result, known := values[s.spec.Interface]
	return result.verdict, result.detail, known && result.verdict != "" && result.verdict != "unknown"
}

func (s *SingBox) buildConfig() (map[string]any, error) {
	outbound, err := outboundFromSpec(s.spec)
	if err != nil {
		return nil, err
	}
	outbound["tag"] = "proxy-out"
	tun, err := tunInboundFromSpec(s.spec, "tun-in")
	if err != nil {
		return nil, err
	}
	config := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"inbounds":  []any{tun},
		"outbounds": []any{outbound},
		"route":     map[string]any{"auto_detect_interface": true, "final": "proxy-out"},
	}
	if len(s.spec.BootstrapDNS) > 0 {
		servers, err := buildBootstrapDNSServers(s.spec.BootstrapDNS, isolatedBootstrapDNSTag)
		if err != nil {
			return nil, err
		}
		config["dns"] = map[string]any{"servers": servers}
		config["route"].(map[string]any)["default_domain_resolver"] = domainResolver("bootstrap-1")
	} else {
		// sing-box 1.12+ requires every dial path which may receive a domain
		// to have an explicit resolver. Using the local resolver preserves the
		// pre-1.12 system-resolution behaviour when the user did not configure
		// dedicated bootstrap DNS, while avoiding a deprecated compatibility
		// switch which is removed in sing-box 1.14.
		config["dns"] = map[string]any{"servers": []any{systemLocalDNSServer()}}
		config["route"].(map[string]any)["default_domain_resolver"] = domainResolver(systemLocalDNSTag)
	}
	return config, nil
}

func tunAddressForSpec(spec TransportSpec) (string, error) {
	if spec.TunAddress == "" {
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(spec.Tag))
		slot := hash.Sum32() % (1 << 14) // 16,384 non-overlapping /30s in 172.19.0.0/16.
		third := slot >> 6
		fourth := (slot & 63) * 4
		return fmt.Sprintf("172.19.%d.%d/30", third, fourth+1), nil
	}
	ip, network, err := net.ParseCIDR(spec.TunAddress)
	if err != nil || ip.To4() == nil {
		return "", fmt.Errorf("tun_address must be an IPv4 /30 host address, got %q", spec.TunAddress)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 30 {
		return "", fmt.Errorf("tun_address must use an IPv4 /30 prefix, got %q", spec.TunAddress)
	}
	host := ip.To4()[3] & 3
	if host == 0 || host == 3 {
		return "", fmt.Errorf("tun_address must be a usable /30 host address, got %q", spec.TunAddress)
	}
	return spec.TunAddress, nil
}

func ValidateUniqueTunAddresses(specs []TransportSpec) error {
	used := make(map[string]string)
	for _, spec := range specs {
		if spec.Type != "sing-box" && spec.Type != "sing-box-vless-reality" {
			continue
		}
		address, err := tunAddressForSpec(spec)
		if err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		_, network, _ := net.ParseCIDR(address)
		subnet := network.String()
		if previous, exists := used[subnet]; exists {
			return fmt.Errorf("transports %q and %q use the same TUN subnet %s; set tun_address manually", previous, spec.Tag, subnet)
		}
		used[subnet] = spec.Tag
	}
	return nil
}

func parseBootstrapDNS(address string) (string, uint16, error) {
	host := address
	port := uint16(53)
	if parsedHost, parsedPort, err := net.SplitHostPort(address); err == nil {
		host = parsedHost
		var numericPort uint64
		if _, err := fmt.Sscanf(parsedPort, "%d", &numericPort); err != nil || numericPort == 0 || numericPort > 65535 {
			return "", 0, fmt.Errorf("invalid bootstrap DNS port in %q", address)
		}
		port = uint16(numericPort)
	} else if len(address) > 0 && address[0] == '[' {
		return "", 0, fmt.Errorf("invalid bootstrap DNS address %q", address)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("bootstrap DNS must be an IP address, got %q", address)
	}
	return host, port, nil
}

const systemLocalDNSTag = "system-local"

func systemLocalDNSServer() map[string]any {
	return map[string]any{
		"type": "local",
		"tag":  systemLocalDNSTag,
	}
}

func domainResolver(server string) map[string]any {
	return map[string]any{
		"server":   server,
		"strategy": "prefer_ipv4",
	}
}

func isolatedBootstrapDNSTag(index int) string {
	return fmt.Sprintf("bootstrap-%d", index+1)
}

func buildBootstrapDNSServers(addresses []string, tagForIndex func(int) string) ([]any, error) {
	servers := make([]any, 0, len(addresses))
	for index, address := range addresses {
		host, port, err := parseBootstrapDNS(address)
		if err != nil {
			return nil, err
		}
		servers = append(servers, map[string]any{
			"type":        "udp",
			"tag":         tagForIndex(index),
			"server":      host,
			"server_port": port,
		})
	}
	return servers, nil
}
