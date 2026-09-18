package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestShareLinkSchemeCaseCompatibility(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"proxy.example","port":"443","id":"example-id","net":"tcp"}`))
	for _, seed := range []string{
		"vmess://" + vmess,
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:example-password")) + "@proxy.example:8388",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:example-password@proxy.example:8388")),
	} {
		scheme, payload, _ := strings.Cut(seed, "://")
		want, err := parseShareLink(seed)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, _ := json.Marshal(want)
		for mask := 0; mask < 1<<len(scheme); mask++ {
			variant := []byte(scheme)
			for index := range variant {
				if mask&(1<<index) != 0 {
					variant[index] -= 'a' - 'A'
				}
			}
			got, err := parseShareLink(string(variant) + "://" + payload)
			gotJSON, _ := json.Marshal(got)
			if err != nil || !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("scheme case changed result: scheme=%s mask=%d err=%v", scheme, mask, err)
			}
		}
	}
}

func TestOutboundJSONTypeCompatibility(t *testing.T) {
	for _, kind := range []string{`null`, `[]`, `{}`, `true`, `1`, `""`, `" \t"`} {
		if _, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"type":` + kind + `}`}); err == nil {
			t.Fatalf("invalid JSON type accepted: %s", kind)
		}
	}
	if _, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"server":"proxy.example"}`}); err == nil {
		t.Fatal("missing type accepted")
	}
	if _, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"type":"future-example-protocol"}`}); err != nil {
		t.Fatal("non-empty protocol extension was restricted")
	}
}

func TestLegacyVLESSPortCompatibility(t *testing.T) {
	for _, port := range []uint16{1, 443, 65535} {
		outbound, err := outboundFromSpec(TransportSpec{VLESS: &VLESSSpec{
			Server: "proxy.example", ServerPort: port, UUID: "example-id", PublicKey: "example-public-key",
		}})
		if err != nil || summariseOutbound(outbound).port != int(port) {
			t.Fatalf("legacy VLESS summary lost port %d: %v", port, err)
		}
		encoded, err := json.Marshal(outbound)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if summariseOutbound(decoded).port != int(port) {
			t.Fatalf("JSON round trip changed legacy VLESS port %d", port)
		}
	}
}
