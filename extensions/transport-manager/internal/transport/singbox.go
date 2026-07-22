package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
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
	opMu               sync.Mutex
	mu                 sync.Mutex
	spec               TransportSpec
	binary, runtimeDir string
	cmd                *exec.Cmd
	done               chan error
	state              State
	lastErr            string
	updated            time.Time
	healthEndpoint     RoutingHealthEndpoint
	healthFailures     int
	server             string
	serverPort         int
	protocol           string
	security           string
	sni                string
	network            string
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
	result := &SingBox{spec: spec, binary: binary, runtimeDir: runtimeDir, state: StateDown, updated: time.Now().UTC()}
	if server, ok := outbound["server"].(string); ok {
		result.server = server
	}
	if protocol, ok := outbound["type"].(string); ok {
		result.protocol = protocol
	}
	result.serverPort, result.security, result.sni, result.network = summariseOutbound(outbound)
	if len(health) > 0 {
		result.healthEndpoint = health[0]
	}
	return result, nil
}

func NewFromSpec(spec TransportSpec, binary, runtimeDir string, health ...RoutingHealthEndpoint) (Transport, error) {
	if !validTag.MatchString(spec.Tag) || !validInterface.MatchString(spec.Interface) {
		return nil, fmt.Errorf("invalid tag or interface")
	}
	if err := validateGeoSpec(spec); err != nil {
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
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(binary); err != nil {
			if binary == "iptables" {
				return fmt.Errorf("%s is required to allow LAN forwarding into %s", binary, s.spec.Interface)
			}
			continue
		}
		args := forwardingRuleArgs(s.spec.Interface)
		if exec.Command(binary, append([]string{"-C"}, args...)...).Run() == nil {
			continue
		}
		output, err := exec.Command(binary, append([]string{"-A"}, args...)...).CombinedOutput()
		if err == nil {
			continue
		}
		// Some older Keenetic kernels do not expose xt_comment. Keep the
		// compatibility rule append-only and reconcile it on every start.
		legacy := []string{"FORWARD", "-o", s.spec.Interface, "-j", "ACCEPT"}
		if exec.Command(binary, append([]string{"-C"}, legacy...)...).Run() == nil {
			continue
		}
		if legacyOutput, legacyErr := exec.Command(binary, append([]string{"-A"}, legacy...)...).CombinedOutput(); legacyErr != nil {
			return fmt.Errorf("allow forwarding into %s with %s: marked rule: %w: %s; compatibility rule: %v: %s", s.spec.Interface, binary, err, string(output), legacyErr, string(legacyOutput))
		}
	}
	return nil
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
	const maximumLogBytes = 2 * 1024 * 1024
	path := filepath.Join(s.runtimeDir, s.spec.Tag+".log")
	if info, err := os.Stat(path); err == nil && info.Size() > maximumLogBytes {
		_ = os.Truncate(path, 0)
	}
}

func (s *SingBox) removeForwardingRules() {
	removeForwardingRules(s.spec.Interface, true)
}

func forwardingRuleArgs(interfaceName string) []string {
	return []string{"FORWARD", "-o", interfaceName, "-m", "comment", "--comment", "keen-pbr-sb:" + interfaceName, "-j", "ACCEPT"}
}

func removeForwardingRules(interfaceName string, includeLegacy bool) {
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(binary); err != nil {
			continue
		}
		rules := [][]string{forwardingRuleArgs(interfaceName)}
		if includeLegacy {
			rules = append(rules, []string{"FORWARD", "-o", interfaceName, "-j", "ACCEPT"})
		}
		for _, args := range rules {
			for exec.Command(binary, append([]string{"-C"}, args...)...).Run() == nil {
				if exec.Command(binary, append([]string{"-D"}, args...)...).Run() != nil {
					break
				}
			}
		}
	}
}

// CleanupForwardingRules removes rules left behind by an unclean manager exit.
// Only interfaces belonging to configured sing-box transports are touched.
func CleanupForwardingRules(specs []TransportSpec) {
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			removeForwardingRules(spec.Interface, true)
		}
	}
}

// CleanupOrphanProcesses terminates sing-box children that survived an
// unclean transport-manager exit. Matching is restricted to the exact config
// paths owned by configured transports in our runtime directory.
func CleanupOrphanProcesses(specs []TransportSpec, runtimeDir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	ownedConfigs := make(map[string]bool)
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			ownedConfigs[filepath.Join(runtimeDir, spec.Tag+".json")] = true
		}
	}
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
		}
	}
	return errors.Join(errs...)
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
	status := Status{Tag: s.spec.Tag, Type: s.spec.Type, Interface: s.spec.Interface, Server: s.server,
		ServerPort: s.serverPort, Protocol: s.protocol, Security: s.security, SNI: s.sni, Network: s.network,
		State: state, PID: pid, Error: s.lastErr, UpdatedAt: s.updated}
	s.mu.Unlock()
	if state == StateUp {
		s.applyRoutingHealth(ctx, &status)
	}
	return status
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
	mtu := s.spec.MTU
	if mtu == 0 && s.spec.VLESS != nil {
		mtu = s.spec.VLESS.MTU
	}
	if mtu == 0 {
		mtu = 1420
	}
	outbound, err := outboundFromSpec(s.spec)
	if err != nil {
		return nil, err
	}
	outbound["tag"] = "proxy-out"
	tunAddress, err := tunAddressForSpec(s.spec)
	if err != nil {
		return nil, err
	}
	config := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": s.spec.Interface, "address": []string{tunAddress}, "mtu": mtu, "stack": "gvisor", "auto_route": false, "strict_route": false}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"auto_detect_interface": true, "final": "proxy-out"},
	}
	if len(s.spec.BootstrapDNS) > 0 {
		servers := make([]any, 0, len(s.spec.BootstrapDNS))
		for index, address := range s.spec.BootstrapDNS {
			host, port, err := parseBootstrapDNS(address)
			if err != nil {
				return nil, err
			}
			servers = append(servers, map[string]any{
				"type": "udp", "tag": fmt.Sprintf("bootstrap-%d", index+1),
				"server": host, "server_port": port,
			})
		}
		config["dns"] = map[string]any{"servers": servers}
		config["route"].(map[string]any)["default_domain_resolver"] = map[string]any{
			"server": "bootstrap-1", "strategy": "prefer_ipv4",
		}
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
