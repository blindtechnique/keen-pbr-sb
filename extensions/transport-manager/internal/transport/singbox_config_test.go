package transport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSingBoxLocalRuntimeReadinessChecksOnlyLocalState(t *testing.T) {
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := &SingBox{
		spec:    TransportSpec{Tag: "proxy", Interface: "vless1"},
		cmd:     &exec.Cmd{Process: process},
		state:   StateUp,
		updated: time.Now().UTC(),
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name}, nil
		},
		runtimeRulesPresent: func(string) bool { return true },
		healthEndpoint: RoutingHealthEndpoint{
			URL: "http://127.0.0.1:1/external-health-must-not-be-used",
		},
	}
	if !s.LocalRuntimeReady() {
		t.Fatal("complete local runtime was not reported ready")
	}
	s.runtimeRulesPresent = func(string) bool { return false }
	if s.LocalRuntimeReady() {
		t.Fatal("missing local runtime rules were reported ready")
	}
}

func TestSingBoxConfigUsesGVisorForPolicyRoutedTun(t *testing.T) {
	s := &SingBox{spec: TransportSpec{
		Tag:          "proxy",
		Type:         "sing-box",
		Interface:    "vless1",
		OutboundJSON: `{"type":"direct"}`,
	}}

	config, err := s.buildConfig()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	inbounds := config["inbounds"].([]any)
	tun := inbounds[0].(map[string]any)

	if got := tun["stack"]; got != "gvisor" {
		t.Fatalf("unexpected TUN stack: got %v, want gvisor", got)
	}
	if got := tun["auto_route"]; got != false {
		t.Fatalf("keen-pbr must retain policy-route ownership, auto_route=%v", got)
	}
	if _, exists := tun["dns_mode"]; exists {
		t.Fatal("dns_mode must not be generated: sing-box 1.13 rejects this TUN field")
	}
}

func TestSingBoxConfigAddsLocalDomainResolverWithoutBootstrapDNS(t *testing.T) {
	s := &SingBox{spec: TransportSpec{
		Tag:          "proxy",
		Type:         "sing-box",
		Interface:    "vless1",
		OutboundJSON: `{"type":"vless","server":"proxy.example","server_port":443,"uuid":"example"}`,
	}}

	config, err := s.buildConfig()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	servers := config["dns"].(map[string]any)["servers"].([]any)
	if len(servers) != 1 || servers[0].(map[string]any)["type"] != "local" ||
		servers[0].(map[string]any)["tag"] != systemLocalDNSTag {
		t.Fatalf("unexpected system resolver: %#v", servers)
	}
	resolver := config["route"].(map[string]any)["default_domain_resolver"].(map[string]any)
	if resolver["server"] != systemLocalDNSTag || resolver["strategy"] != "prefer_ipv4" {
		t.Fatalf("unexpected default domain resolver: %#v", resolver)
	}
}

func TestSingBoxConfigAddsBootstrapDNS(t *testing.T) {
	s := &SingBox{spec: TransportSpec{
		Tag: "proxy", Type: "sing-box", Interface: "vless1",
		OutboundJSON: `{"type":"direct"}`,
		BootstrapDNS: []string{"1.1.1.1", "[2606:4700:4700::1111]:5353"},
	}}
	config, err := s.buildConfig()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 2 || servers[0].(map[string]any)["server"] != "1.1.1.1" {
		t.Fatalf("unexpected bootstrap DNS servers: %#v", servers)
	}
	resolver := config["route"].(map[string]any)["default_domain_resolver"].(map[string]any)
	if resolver["server"] != "bootstrap-1" {
		t.Fatalf("unexpected default domain resolver: %#v", resolver)
	}
}

func TestSingBoxConfigRejectsHostnameAsBootstrapDNS(t *testing.T) {
	s := &SingBox{spec: TransportSpec{
		Tag: "proxy", Type: "sing-box", Interface: "vless1",
		OutboundJSON: `{"type":"direct"}`, BootstrapDNS: []string{"dns.example.com"},
	}}
	if _, err := s.buildConfig(); err == nil {
		t.Fatal("expected hostname bootstrap DNS to be rejected")
	}
}

func TestTransportGeoModeRequiresExplicitValidManualCountry(t *testing.T) {
	base := TransportSpec{Tag: "proxy", Type: "native", Interface: "nwg0"}
	for _, mode := range []string{"", "disabled", "auto"} {
		spec := base
		spec.GeoMode = mode
		if _, err := NewFromSpec(spec, "sing-box", t.TempDir()); err != nil {
			t.Fatalf("geo mode %q should be valid: %v", mode, err)
		}
	}

	invalid := base
	invalid.GeoMode = "manual"
	invalid.CountryCode = "DEU"
	if _, err := NewFromSpec(invalid, "sing-box", t.TempDir()); err == nil {
		t.Fatal("manual geo mode accepted an invalid country code")
	}

	valid := base
	valid.GeoMode = "manual"
	valid.CountryCode = "DE"
	valid.Country = "Germany"
	if _, err := NewFromSpec(valid, "sing-box", t.TempDir()); err != nil {
		t.Fatalf("valid manual geo mode was rejected: %v", err)
	}
}

func TestSingBoxConfigAssignsUniqueDeterministicTunAddresses(t *testing.T) {
	address := func(tag string) string {
		s := &SingBox{spec: TransportSpec{Tag: tag, Type: "sing-box", Interface: tag, OutboundJSON: `{"type":"direct"}`}}
		config, err := s.buildConfig()
		if err != nil {
			t.Fatalf("build config for %s: %v", tag, err)
		}
		return config["inbounds"].([]any)[0].(map[string]any)["address"].([]string)[0]
	}
	first := address("proxy_one")
	second := address("proxy_two")
	if first == second {
		t.Fatalf("parallel transports received the same TUN address: %s", first)
	}
	if repeated := address("proxy_one"); repeated != first {
		t.Fatalf("TUN address is not deterministic: %s != %s", repeated, first)
	}
}

func TestSingBoxConfigHonoursTunAddressOverride(t *testing.T) {
	s := &SingBox{spec: TransportSpec{Tag: "proxy", Type: "sing-box", Interface: "vless1", TunAddress: "10.77.0.1/30", OutboundJSON: `{"type":"direct"}`}}
	config, err := s.buildConfig()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	got := config["inbounds"].([]any)[0].(map[string]any)["address"].([]string)[0]
	if got != "10.77.0.1/30" {
		t.Fatalf("unexpected TUN override: %s", got)
	}
}

func TestSingBoxConfigRejectsInvalidTunAddressOverride(t *testing.T) {
	_, err := NewSingBox(TransportSpec{Tag: "proxy", Type: "sing-box", Interface: "vless1", TunAddress: "10.77.0.0/24", OutboundJSON: `{"type":"direct"}`}, "sing-box", t.TempDir())
	if err == nil {
		t.Fatal("expected invalid TUN address to be rejected")
	}
}

func TestRoutingHealthRequiresThreeConsecutiveFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		_, _ = w.Write([]byte(`{"outbounds":[{"interfaces":[{"interface_name":"vless1","status":"unavailable","detail":"probe failed"}]}]}`))
	}))
	defer server.Close()

	s := &SingBox{spec: TransportSpec{Interface: "vless1"}, healthEndpoint: RoutingHealthEndpoint{URL: server.URL, APIKey: "secret"}}
	for attempt := 1; attempt <= 3; attempt++ {
		status := Status{State: StateUp}
		s.applyRoutingHealth(context.Background(), &status)
		if attempt < 3 && status.State != StateUp {
			t.Fatalf("attempt %d degraded too early", attempt)
		}
		if attempt == 3 && status.State != StateDegraded {
			t.Fatal("third consecutive failed routing verdict must degrade the transport")
		}
	}
}

func TestValidateUniqueTunAddressesRejectsManualCollision(t *testing.T) {
	err := ValidateUniqueTunAddresses([]TransportSpec{
		{Tag: "one", Type: "sing-box", TunAddress: "10.77.0.1/30"},
		{Tag: "two", Type: "sing-box", TunAddress: "10.77.0.2/30"},
	})
	if err == nil {
		t.Fatal("expected duplicate /30 subnet to be rejected")
	}
}

func TestMatchesOwnedSingBoxCommand(t *testing.T) {
	owned := map[string]bool{"/run/keen-pbr/proxy.json": true}
	if !matchesOwnedSingBoxCommand([]byte("/opt/bin/sing-box\x00run\x00-c\x00/run/keen-pbr/proxy.json\x00"), owned) {
		t.Fatal("expected managed sing-box command to match")
	}
	if !matchesOwnedSingBoxCommand([]byte("/opt/lib/ld-2.27.so\x00--library-path\x00/opt/lib:/opt/usr/lib\x00/opt/bin/sing-box.real\x00run\x00-c\x00/run/keen-pbr/proxy.json\x00"), owned) {
		t.Fatal("expected Entware loader-wrapped sing-box command to match")
	}
	if matchesOwnedSingBoxCommand([]byte("/opt/bin/sing-box\x00run\x00-c\x00/opt/etc/other.json\x00"), owned) {
		t.Fatal("unrelated sing-box process must not match")
	}
	if matchesOwnedSingBoxCommand([]byte("/bin/sh\x00-c\x00/run/keen-pbr/proxy.json\x00"), owned) {
		t.Fatal("non-sing-box process must not match")
	}
}

func TestOwnedSingBoxConfigPathsIncludesEmptySharedRuntimeOnlyInSharedMode(t *testing.T) {
	runtimeDir := filepath.Join("run", "keen-pbr")
	isolated := ownedSingBoxConfigPaths(nil, runtimeDir, false)
	if len(isolated) != 0 {
		t.Fatalf("empty isolated mode unexpectedly owns configs: %#v", isolated)
	}
	shared := ownedSingBoxConfigPaths(nil, runtimeDir, true)
	sharedPath := filepath.Join(runtimeDir, "shared.json")
	if len(shared) != 1 || !shared[sharedPath] {
		t.Fatalf("empty shared mode does not own its exact crash-recovery config: %#v", shared)
	}
}
