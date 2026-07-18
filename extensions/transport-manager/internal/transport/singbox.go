package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var (
	validTag       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
	validInterface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
)

type TransportSpec struct {
	Tag          string     `json:"tag"`
	Type         string     `json:"type"`
	Interface    string     `json:"interface"`
	AutoStart    bool       `json:"auto_start,omitempty"`
	Link         string     `json:"link,omitempty"`
	OutboundJSON string     `json:"outbound_json,omitempty"`
	MTU          uint32     `json:"mtu,omitempty"`
	BootstrapDNS []string   `json:"bootstrap_dns,omitempty"`
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
}

func NewSingBox(spec TransportSpec, binary, runtimeDir string) (*SingBox, error) {
	if !validTag.MatchString(spec.Tag) || !validInterface.MatchString(spec.Interface) {
		return nil, fmt.Errorf("tag and interface are required")
	}
	if _, err := outboundFromSpec(spec); err != nil {
		return nil, err
	}
	return &SingBox{spec: spec, binary: binary, runtimeDir: runtimeDir, state: StateDown, updated: time.Now().UTC()}, nil
}

func NewFromSpec(spec TransportSpec, binary, runtimeDir string) (Transport, error) {
	if !validTag.MatchString(spec.Tag) || !validInterface.MatchString(spec.Interface) {
		return nil, fmt.Errorf("invalid tag or interface")
	}
	switch spec.Type {
	case "native":
		return NewNative(spec.Tag, spec.Interface), nil
	case "sing-box", "sing-box-vless-reality":
		return NewSingBox(spec, binary, runtimeDir)
	default:
		return nil, fmt.Errorf("unsupported type %q", spec.Type)
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
		args := []string{"FORWARD", "-o", s.spec.Interface, "-j", "ACCEPT"}
		if exec.Command(binary, append([]string{"-C"}, args...)...).Run() == nil {
			continue
		}
		if output, err := exec.Command(binary, append([]string{"-I"}, args...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("allow forwarding into %s with %s: %w: %s", s.spec.Interface, binary, err, string(output))
		}
	}
	return nil
}

func (s *SingBox) removeForwardingRules() {
	for _, binary := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(binary); err != nil {
			continue
		}
		args := []string{"FORWARD", "-o", s.spec.Interface, "-j", "ACCEPT"}
		for exec.Command(binary, append([]string{"-C"}, args...)...).Run() == nil {
			if exec.Command(binary, append([]string{"-D"}, args...)...).Run() != nil {
				break
			}
		}
	}
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

func (s *SingBox) Status(context.Context) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	return Status{Tag: s.spec.Tag, Type: s.spec.Type, Interface: s.spec.Interface, State: state, PID: pid, Error: s.lastErr, UpdatedAt: s.updated}
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
	config := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": s.spec.Interface, "address": []string{"172.19.0.1/30"}, "mtu": mtu, "stack": "gvisor", "dns_mode": "disabled", "auto_route": false, "strict_route": false}},
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
