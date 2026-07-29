package transport

import (
	"encoding/json"
	"reflect"
	"testing"
)

func sharedConfigSpec(tag, interfaceName, server string) TransportSpec {
	return TransportSpec{
		Tag:          tag,
		Type:         "sing-box",
		Interface:    interfaceName,
		OutboundJSON: `{"type":"vless","server":"` + server + `","server_port":443,"uuid":"example"}`,
	}
}

func TestSharedSingBoxConfigIsDeterministic(t *testing.T) {
	first := sharedConfigSpec("proxy_b", "vless2", "b.example")
	second := sharedConfigSpec("proxy_a", "vless1", "a.example")
	native := TransportSpec{Tag: "native", Type: "native", Interface: "nwg0"}

	left, err := BuildSharedSingBoxConfig([]TransportSpec{first, native, second})
	if err != nil {
		t.Fatalf("build shared config: %v", err)
	}
	right, err := BuildSharedSingBoxConfig([]TransportSpec{second, first, native})
	if err != nil {
		t.Fatalf("build reordered shared config: %v", err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("shared config depends on input order:\n%s\n%s", leftJSON, rightJSON)
	}

	inbounds := left["inbounds"].([]any)
	if got := inbounds[0].(map[string]any)["interface_name"]; got != "vless1" {
		t.Fatalf("expected transports sorted by stable tag, got first interface %v", got)
	}
}

func TestSharedSingBoxConfigRoutesEachTunOnlyToItsProxy(t *testing.T) {
	config, err := BuildSharedSingBoxConfig([]TransportSpec{
		sharedConfigSpec("proxy_a", "vless1", "a.example"),
		sharedConfigSpec("proxy_b", "vless2", "b.example"),
	})
	if err != nil {
		t.Fatalf("build shared config: %v", err)
	}

	rules := config["route"].(map[string]any)["rules"].([]any)
	want := []map[string]any{
		{"inbound": []string{"tun-in-proxy_a"}, "action": "route", "outbound": "proxy-out-proxy_a"},
		{"inbound": []string{"tun-in-proxy_b"}, "action": "route", "outbound": "proxy-out-proxy_b"},
	}
	for index, expected := range want {
		if !reflect.DeepEqual(rules[index], expected) {
			t.Fatalf("unexpected route rule %d: got %#v, want %#v", index, rules[index], expected)
		}
	}
	if got := config["route"].(map[string]any)["final"]; got != "direct-out" {
		t.Fatalf("unexpected shared fallback outbound: %v", got)
	}
}

func TestSharedSingBoxConfigKeepsBootstrapDNSPerProxy(t *testing.T) {
	first := sharedConfigSpec("proxy_a", "vless1", "a.example")
	first.BootstrapDNS = []string{"1.1.1.1"}
	second := sharedConfigSpec("proxy_b", "vless2", "b.example")
	second.BootstrapDNS = []string{"9.9.9.9:5353"}

	config, err := BuildSharedSingBoxConfig([]TransportSpec{second, first})
	if err != nil {
		t.Fatalf("build shared config: %v", err)
	}
	servers := config["dns"].(map[string]any)["servers"].([]any)
	if got := servers[0].(map[string]any)["tag"]; got != "bootstrap-proxy_a-1" {
		t.Fatalf("unexpected first DNS tag: %v", got)
	}
	if got := servers[1].(map[string]any)["server_port"]; got != uint16(5353) {
		t.Fatalf("unexpected second DNS port: %#v", got)
	}

	outbounds := config["outbounds"].([]any)
	firstResolver := outbounds[0].(map[string]any)["domain_resolver"].(map[string]any)
	secondResolver := outbounds[1].(map[string]any)["domain_resolver"].(map[string]any)
	if firstResolver["server"] != "bootstrap-proxy_a-1" ||
		secondResolver["server"] != "bootstrap-proxy_b-1" {
		t.Fatalf("bootstrap DNS leaked between proxies: %#v / %#v", firstResolver, secondResolver)
	}
}

func TestSharedSingBoxValidationMatchesIsolatedMetadataRules(t *testing.T) {
	for name, mutate := range map[string]func(*TransportSpec){
		"control character in display name": func(spec *TransportSpec) {
			spec.DisplayName = "proxy\nname"
		},
		"unsupported geo mode": func(spec *TransportSpec) {
			spec.GeoMode = "guess"
		},
		"invalid manual country": func(spec *TransportSpec) {
			spec.GeoMode = "manual"
			spec.CountryCode = "RUS"
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := sharedConfigSpec("proxy_a", "vless1", "a.example")
			mutate(&spec)
			if _, err := BuildSharedSingBoxConfig([]TransportSpec{spec}); err == nil {
				t.Fatal("shared mode accepted metadata rejected by isolated mode")
			}
			if _, err := NewFromSpec(spec, "sing-box", t.TempDir()); err == nil {
				t.Fatal("isolated validation unexpectedly accepted the same metadata")
			}
		})
	}
}

func TestSharedSingBoxConfigRejectsConflictingTunOwnership(t *testing.T) {
	first := sharedConfigSpec("proxy_a", "vless1", "a.example")
	second := sharedConfigSpec("proxy_b", "vless1", "b.example")
	if _, err := BuildSharedSingBoxConfig([]TransportSpec{first, second}); err == nil {
		t.Fatal("expected duplicate TUN interface to be rejected")
	}

	second.Interface = "vless2"
	first.TunAddress = "10.77.0.1/30"
	second.TunAddress = "10.77.0.2/30"
	if _, err := BuildSharedSingBoxConfig([]TransportSpec{first, second}); err == nil {
		t.Fatal("expected duplicate TUN subnet to be rejected")
	}
}

func TestSharedSingBoxConfigRequiresManagedProxy(t *testing.T) {
	if _, err := BuildSharedSingBoxConfig([]TransportSpec{{
		Tag: "native", Type: "native", Interface: "nwg0",
	}}); err == nil {
		t.Fatal("expected empty managed proxy set to be rejected")
	}
}
