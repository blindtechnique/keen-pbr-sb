package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Synthetic inputs only: never seed from subscriptions, HARs or router backups.
// This bounds the mutation workload, not the production import contract. The
// API batch has a larger bound, tested separately in internal/api.
const fuzzParserMaxBytes = 64 << 10

const fuzzVLESSLink = "vless://00000000-0000-0000-0000-000000000001@proxy.example:443?security=reality&sni=cdn.example&pbk=example-public-key&type=ws&path=%2Ftest"
const fuzzVMessPayload = `{"add":"proxy.example","port":"8443","id":"00000000-0000-0000-0000-000000000002","net":"grpc","path":"example","tls":"tls"}`

func shareLinkFuzzSeeds() []string {
	return []string{
		"", "not a URI", "tuic://proxy.example:443", "vless://id@[2001:db8::1]:65536",
		"vless://id@proxy.example:0", "vless://id@proxy.example:443?path=%xx",
		fuzzVLESSLink,
		"vless://id@[2001:db8::1]:443?type=http&host=a.example,b.example&alpn=h2,http%2F1.1#Example",
		"trojan://example-password@proxy.example:443?type=httpupgrade&path=%2Fws",
		"hy2://example-password@proxy.example:443?obfs=salamander&obfs-password=example-mask",
		"hysteria2://example-user:example-password@proxy.example:443?upmbps=10&downmbps=20",
		"tuic://example-id:example-password@proxy.example:443?congestion_control=bbr",
		"anytls://example-password@proxy.example:443?insecure=1",
		"naive+https://example-user:example-password@proxy.example:443",
		"naive+quic://example-user:example-password@proxy.example:443",
		"socks5://example-user:example-password@proxy.example:1080",
		"http://proxy.example:8080", "https://proxy.example:443",
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(fuzzVMessPayload)),
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:example-password")) + "@proxy.example:8388#Example",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:example-password@[2001:db8::1]:8388")),
	}
}

func fuzzJSON(t *testing.T, value any, inputBytes int) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("accepted value is not JSON-serializable: %T", err)
	}
	// Account for JSON escaping, repeated endpoint/TLS fields and the fixed
	// generated TUN/DNS/route envelope. No input or credential in diagnostics.
	if len(encoded) > 32*inputBytes+8192 {
		t.Fatalf("output expansion exceeded bound: input=%d output=%d", inputBytes, len(encoded))
	}
	return encoded
}

func assertShareLinkResult(t *testing.T, outbound map[string]any, inputBytes int) {
	t.Helper()
	protocol, typeOK := outbound["type"].(string)
	server, serverOK := outbound["server"].(string)
	port, portOK := outbound["server_port"].(int)
	if !typeOK || protocol == "" || !serverOK || server == "" || !portOK || port < 1 || port > 65535 {
		t.Fatal("accepted share link has no valid protocol/endpoint")
	}
	assertOutboundSummaryRoundTrip(t, outbound, inputBytes)
}

func assertOutboundSummaryRoundTrip(t *testing.T, outbound map[string]any, inputBytes int) {
	t.Helper()
	encoded := fuzzJSON(t, outbound, inputBytes)
	// Also exercise summary handling after the JSON number representation
	// changes from int to float64, as it does at the transport API boundary.
	var reloaded map[string]any
	if err := json.Unmarshal(encoded, &reloaded); err != nil {
		t.Fatal("accepted outbound did not round-trip")
	}
	before, after := summariseOutbound(outbound), summariseOutbound(reloaded)
	// encoding/json deliberately replaces invalid UTF-8 in strings. Arbitrary
	// byte mutations may contain it; compare the same JSON representation,
	// not raw Go strings against their normalized version after decoding.
	beforeMetadata := []any{before.path, before.port, before.security, before.sni}
	afterMetadata := []any{after.path, after.port, after.security, after.sni}
	var beforeNormalized, afterNormalized []any
	_ = json.Unmarshal(fuzzJSON(t, beforeMetadata, inputBytes), &beforeNormalized)
	_ = json.Unmarshal(fuzzJSON(t, afterMetadata, inputBytes), &afterNormalized)
	if !reflect.DeepEqual(beforeNormalized, afterNormalized) {
		t.Fatal("outbound summary changed after JSON round-trip")
	}
}

func FuzzShareLink(f *testing.F) {
	for _, seed := range shareLinkFuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > fuzzParserMaxBytes {
			return
		}
		link := strings.TrimSpace(input)
		outbound, err := parseShareLink(link)
		if err == nil {
			assertShareLinkResult(t, outbound, len(link))
		}
		// A URI scheme is case-insensitive; the payload (including base64 and
		// credentials) is not. Do not lowercase the entire input to test this.
		colon := strings.IndexByte(link, ':')
		if colon < 1 {
			return
		}
		scheme := []byte(link[:colon])
		for index, char := range scheme {
			if index%2 == 0 && char >= 'a' && char <= 'z' {
				scheme[index] = char - ('a' - 'A')
			} else if index%2 == 1 && char >= 'A' && char <= 'Z' {
				scheme[index] = char + ('a' - 'A')
			}
		}
		other, otherErr := parseShareLink(string(scheme) + link[colon:])
		if (err == nil) != (otherErr == nil) {
			t.Fatal("scheme case changed acceptance")
		}
		if err == nil && !bytes.Equal(fuzzJSON(t, outbound, len(link)), fuzzJSON(t, other, len(link))) {
			t.Fatal("scheme case changed connection parameters")
		}
	})
}

func FuzzBase64Payload(f *testing.F) {
	for _, seed := range [][]byte{
		nil, []byte(fuzzVMessPayload), []byte(`{"port":1e999}`), []byte("null"),
		[]byte("aes-256-gcm:example-password@proxy.example:8388"),
		[]byte("aes-256-gcm:example-password@[2001:db8::1]:8388"),
		[]byte("invalid=base64"), {0xff, 0, '\r', '\n'},
	} {
		for variant := byte(0); variant < 4; variant++ {
			f.Add(seed, variant)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte, variant byte) {
		if len(input) > fuzzParserMaxBytes/2 {
			return
		}
		// Raw mutations cover rejected padding/alphabet/whitespace as well.
		if decoded, err := decodeBase64(string(input)); err == nil && len(decoded) > len(input) {
			t.Fatal("base64 decoder expanded its input")
		}
		encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
		encoded := encodings[int(variant)%len(encodings)].EncodeToString(input)
		decoded, err := decodeBase64(" \t" + encoded + "\r\n")
		if err != nil || !bytes.Equal(decoded, input) {
			t.Fatal("base64 round-trip failed")
		}
		canonical := base64.RawStdEncoding.EncodeToString(input)
		for _, scheme := range []string{"vmess://", "ss://"} {
			outbound, parseErr := parseShareLink(scheme + encoded)
			other, otherErr := parseShareLink(scheme + canonical)
			if (parseErr == nil) != (otherErr == nil) {
				t.Fatal("base64 alphabet/padding changed link acceptance")
			}
			if parseErr == nil {
				assertShareLinkResult(t, outbound, len(encoded))
				if !bytes.Equal(fuzzJSON(t, outbound, len(encoded)), fuzzJSON(t, other, len(encoded))) {
					t.Fatal("base64 alphabet/padding changed connection parameters")
				}
			}
		}
	})
}

func FuzzTransportConfig(f *testing.F) {
	for _, seed := range shareLinkFuzzSeeds() {
		f.Add(seed, byte(0))
	}
	for _, seed := range []string{
		`null`, `{}`, `{"type":null}`, `{"type":[]}`, `{"type":{}}`, `{"type":17}`, `{"type":" "}`,
		`{"type":"ssh","server":"proxy.example","server_port":22,"user":"example"}`,
		`{"type":"vless","server":"proxy.example","server_port":443,"tls":[],"transport":{"type":"ws"}}`,
		`{"type":"shadowsocks","server":"proxy.example","network":["tcp",false,"udp",{},"tcp"]}`,
	} {
		f.Add(seed, byte(1))
	}
	f.Add(`{"tag":"fuzz_a","type":"sing-box","interface":"fuzz0","outbound_json":"{\"type\":\"direct\"}","bootstrap_dns":["192.0.2.1:53"]}`, byte(2))
	f.Add(`{"tag":"fuzz_a","type":"sing-box","interface":"fuzz0","vless":{"server":"proxy.example","server_port":443,"uuid":"example-id","public_key":"example-public-key"}}`, byte(2))
	f.Fuzz(func(t *testing.T, input string, kind byte) {
		if len(input) > fuzzParserMaxBytes {
			return
		}
		spec := TransportSpec{Tag: "fuzz_a", Type: "sing-box", Interface: "fuzz0"}
		switch kind % 3 {
		case 0:
			spec.Link = input
		case 1:
			spec.OutboundJSON = input
		case 2:
			if err := json.Unmarshal([]byte(input), &spec); err != nil {
				return
			}
		}
		if spec.Type != "sing-box" && spec.Type != "sing-box-vless-reality" {
			return
		}
		if err := ValidateTransportSpec(spec); err != nil {
			return
		}
		before := fuzzJSON(t, spec, len(input))
		// Pure builders only. Never create a manager, start sing-box, resolve
		// endpoints, write files or touch interfaces/firewall from a fuzz case.
		isolated, isolatedErr := (&SingBox{spec: spec}).buildConfig()
		shared, sharedErr := BuildSharedSingBoxConfig([]TransportSpec{spec})
		if (isolatedErr == nil) != (sharedErr == nil) {
			t.Fatal("isolated/shared builders disagree on a single transport")
		}
		if !bytes.Equal(before, fuzzJSON(t, spec, len(input))) {
			t.Fatal("config builder mutated input spec")
		}
		if isolatedErr != nil {
			return
		}
		for _, config := range []map[string]any{isolated, shared} {
			fuzzJSON(t, config, len(input))
			inbounds := config["inbounds"].([]any)
			if len(inbounds) != 1 {
				t.Fatal("builder changed inbound cardinality")
			}
			inbound := inbounds[0].(map[string]any)
			if inbound["auto_route"] != false || inbound["strict_route"] != false || inbound["interface_name"] != spec.Interface {
				t.Fatal("builder escaped the assigned TUN contract")
			}
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			protocol, ok := outbound["type"].(string)
			if !ok || strings.TrimSpace(protocol) == "" {
				t.Fatal("accepted outbound type is not a non-empty string")
			}
			assertOutboundSummaryRoundTrip(t, outbound, len(input))
		}
		second, err := BuildSharedSingBoxConfig([]TransportSpec{spec})
		if err != nil || !bytes.Equal(fuzzJSON(t, shared, len(input)), fuzzJSON(t, second, len(input))) {
			t.Fatal("shared config construction is not deterministic")
		}
	})
}
