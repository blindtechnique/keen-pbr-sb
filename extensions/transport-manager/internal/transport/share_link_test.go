package transport

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseVLESSRealityLink(t *testing.T) {
	outbound, err := parseShareLink("vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&sni=cdn.example.com&fp=chrome&pbk=public-key&sid=0123&type=ws&path=%2Fproxy&host=edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "vless" || outbound["server"] != "example.com" || outbound["server_port"] != 443 {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
	tls := outbound["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "public-key" || reality["short_id"] != "0123" {
		t.Fatalf("unexpected reality: %#v", reality)
	}
	transport := outbound["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/proxy" {
		t.Fatalf("unexpected transport: %#v", transport)
	}
}

func TestParseVMessLink(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"add": "vmess.example.com", "port": "8443", "id": "00000000-0000-0000-0000-000000000002",
		"aid": "0", "scy": "auto", "net": "grpc", "path": "service", "tls": "tls", "sni": "cdn.example.com",
	})
	link := "vmess://" + base64.RawStdEncoding.EncodeToString(payload)
	outbound, err := parseShareLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "vmess" || outbound["server_port"] != 8443 {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
	if outbound["transport"].(map[string]any)["service_name"] != "service" {
		t.Fatalf("unexpected transport: %#v", outbound["transport"])
	}
}

func TestParseShadowsocksLink(t *testing.T) {
	credentials := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	outbound, err := parseShareLink("ss://" + credentials + "@ss.example.com:8388#test")
	if err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "shadowsocks" || outbound["method"] != "aes-256-gcm" || outbound["password"] != "secret" {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
}

func TestParseHysteria2AndTUICLinks(t *testing.T) {
	hy2, err := parseShareLink("hy2://secret@hy.example.com:443?sni=cdn.example.com&obfs=salamander&obfs-password=mask")
	if err != nil {
		t.Fatal(err)
	}
	if hy2["type"] != "hysteria2" || hy2["obfs"].(map[string]any)["password"] != "mask" {
		t.Fatalf("unexpected hysteria2 outbound: %#v", hy2)
	}
	tuic, err := parseShareLink("tuic://00000000-0000-0000-0000-000000000003:secret@tuic.example.com:443?sni=cdn.example.com&congestion_control=bbr")
	if err != nil {
		t.Fatal(err)
	}
	if tuic["type"] != "tuic" || tuic["congestion_control"] != "bbr" {
		t.Fatalf("unexpected tuic outbound: %#v", tuic)
	}
}

func TestOutboundJSONAllowsAnySingBoxProtocol(t *testing.T) {
	outbound, err := outboundFromSpec(TransportSpec{OutboundJSON: `{"type":"ssh","server":"example.com","server_port":22,"user":"root"}`})
	if err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "ssh" {
		t.Fatalf("unexpected outbound: %#v", outbound)
	}
}

func TestRejectsUnsupportedLink(t *testing.T) {
	if _, err := parseShareLink("wireguard://not-a-standard-link"); err == nil {
		t.Fatal("expected unsupported link to fail")
	}
}
