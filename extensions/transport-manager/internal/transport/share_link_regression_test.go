package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FUZZ-01 seed regressions: scheme case must not change opaque payloads, and
// JSON's type must actually be a string. Unknown non-empty protocol names
// remain supported for the advanced sing-box outbound editor.
func TestEncodedShareLinkSchemeCase(t *testing.T) {
	for _, seed := range []string{
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(fuzzVMessPayload)),
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:example-password")) + "@proxy.example:8388",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:example-password@proxy.example:8388")),
	} {
		scheme, payload, _ := strings.Cut(seed, "://")
		want, err := parseShareLink(seed)
		if err != nil {
			t.Fatal("invalid synthetic regression seed")
		}
		wantJSON, _ := json.Marshal(want)
		// Every upper/lower combination, not just all-upper and all-lower.
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
				t.Fatalf("encoded scheme case changed result: scheme=%s mask=%d", scheme, mask)
			}
		}
	}
}

func TestOutboundJSONRequiresStringType(t *testing.T) {
	for _, kind := range []string{`null`, `[]`, `{}`, `true`, `1`, `""`, `" \t"`} {
		if _, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"type":` + kind + `}`}); err == nil {
			t.Fatal("invalid JSON type accepted")
		}
	}
	if _, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"type":"future-example-protocol"}`}); err != nil {
		t.Fatal("advanced outbound protocol extension was restricted")
	}
}

func TestLegacyVLESSPortSurvivesOutboundSummary(t *testing.T) {
	for _, port := range []uint16{1, 443, 65535} {
		outbound, err := outboundFromSpec(TransportSpec{VLESS: &VLESSSpec{
			Server: "proxy.example", ServerPort: port, UUID: "example-id", PublicKey: "example-public-key",
		}})
		if err != nil || summariseOutbound(outbound).port != int(port) {
			t.Fatalf("legacy VLESS summary lost port %d", port)
		}
		assertOutboundSummaryRoundTrip(t, outbound, 1024)
	}
}

func TestParserBoundedLargeInputs(t *testing.T) {
	// Exercise the public subscription's existing 1 MiB headroom too; the
	// smaller fuzz mutation cap must not become a new production restriction.
	for _, size := range []int{64 << 10, 1 << 20} {
		password := strings.Repeat("x", size-128)
		link := "trojan://" + password + "@proxy.example:443"
		outbound, err := parseShareLink(link)
		if err != nil || outbound["password"] != password {
			t.Fatalf("bounded long link changed: size=%d", size)
		}
		fuzzJSON(t, outbound, len(link))
		input := strings.Repeat("A", size-1) + "!"
		if _, err := decodeBase64(input); err == nil {
			t.Fatal("invalid final base64 byte accepted")
		}
		// Wide and deep JSON/query inputs cover allocation and nesting paths
		// under the process memory/time budget without a flaky wall-clock test.
		_, _ = parseShareLink(fuzzVLESSLink + "&alpn=" + strings.Repeat("x,", size/2))
		deep := `{"type":"ssh","extra":` + strings.Repeat("[", size/2) + strings.Repeat("]", size/2) + `}`
		if _, err := outboundFromSpec(TransportSpec{OutboundJSON: deep}); err == nil {
			t.Fatal("JSON nesting beyond the standard decoder limit was accepted")
		}
	}
}
