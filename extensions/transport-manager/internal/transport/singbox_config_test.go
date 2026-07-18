package transport

import "testing"

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
