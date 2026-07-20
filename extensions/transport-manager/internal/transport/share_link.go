package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func outboundFromSpec(spec TransportSpec) (map[string]any, error) {
	if strings.TrimSpace(spec.Link) != "" {
		return parseShareLink(strings.TrimSpace(spec.Link))
	}
	if strings.TrimSpace(spec.OutboundJSON) != "" {
		var outbound map[string]any
		if err := json.Unmarshal([]byte(spec.OutboundJSON), &outbound); err != nil {
			return nil, fmt.Errorf("invalid sing-box outbound JSON: %w", err)
		}
		if outbound["type"] == nil || outbound["type"] == "" {
			return nil, fmt.Errorf("sing-box outbound JSON must contain type")
		}
		return outbound, nil
	}
	if spec.VLESS != nil {
		return legacyVLESSOutbound(spec.VLESS)
	}
	return nil, fmt.Errorf("connection link or sing-box outbound JSON is required")
}

func legacyVLESSOutbound(v *VLESSSpec) (map[string]any, error) {
	if v.Server == "" || v.ServerPort == 0 || v.UUID == "" || v.PublicKey == "" {
		return nil, fmt.Errorf("vless server, uuid and public_key are required")
	}
	fingerprint := v.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	return map[string]any{
		"type": "vless", "server": v.Server, "server_port": v.ServerPort,
		"uuid": v.UUID, "flow": v.Flow,
		"tls": map[string]any{
			"enabled": true, "server_name": v.ServerName,
			"utls":    map[string]any{"enabled": true, "fingerprint": fingerprint},
			"reality": map[string]any{"enabled": true, "public_key": v.PublicKey, "short_id": v.ShortID},
		},
	}, nil
}

func parseShareLink(link string) (map[string]any, error) {
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return parseVMessLink(link)
	}
	if strings.HasPrefix(strings.ToLower(link), "ss://") {
		return parseShadowsocksLink(link)
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid connection link: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		return parseVLESSLink(u)
	case "trojan":
		return parseTrojanLink(u)
	case "hysteria2", "hy2":
		return parseHysteria2Link(u)
	case "tuic":
		return parseTUICLink(u)
	case "anytls":
		return parseAnyTLSLink(u)
	case "socks", "socks5", "http", "https":
		return parseProxyLink(u)
	default:
		return nil, fmt.Errorf("unsupported connection link scheme %q", u.Scheme)
	}
}

func parseVLESSLink(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	uuid := userName(u)
	if uuid == "" {
		return nil, fmt.Errorf("vless link is missing UUID")
	}
	q := u.Query()
	out := map[string]any{"type": "vless", "server": server, "server_port": port, "uuid": uuid}
	setString(out, "flow", q.Get("flow"))
	setString(out, "packet_encoding", first(q, "packetEncoding", "packet_encoding"))
	if tls := tlsFromQuery(q, server, false); tls != nil {
		out["tls"] = tls
	}
	if transport := v2rayTransport(q); transport != nil {
		out["transport"] = transport
	}
	return out, nil
}

func parseTrojanLink(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	password := userName(u)
	if password == "" {
		return nil, fmt.Errorf("trojan link is missing password")
	}
	q := u.Query()
	out := map[string]any{"type": "trojan", "server": server, "server_port": port, "password": password}
	if tls := tlsFromQuery(q, server, true); tls != nil {
		out["tls"] = tls
	}
	if transport := v2rayTransport(q); transport != nil {
		out["transport"] = transport
	}
	return out, nil
}

func parseHysteria2Link(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	password := userName(u)
	if u.User != nil {
		if value, ok := u.User.Password(); ok {
			password = userName(u) + ":" + value
		}
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2 link is missing password")
	}
	q := u.Query()
	out := map[string]any{"type": "hysteria2", "server": server, "server_port": port, "password": password, "tls": tlsFromQuery(q, server, true)}
	if obfsType := first(q, "obfs", "obfs-type"); obfsType != "" {
		out["obfs"] = map[string]any{"type": obfsType, "password": first(q, "obfs-password", "obfs_password")}
	}
	setNumber(out, "up_mbps", first(q, "upmbps", "up_mbps"))
	setNumber(out, "down_mbps", first(q, "downmbps", "down_mbps"))
	return out, nil
}

func parseTUICLink(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	uuid := userName(u)
	password, _ := u.User.Password()
	if uuid == "" || password == "" {
		return nil, fmt.Errorf("tuic link is missing UUID or password")
	}
	q := u.Query()
	out := map[string]any{"type": "tuic", "server": server, "server_port": port, "uuid": uuid, "password": password, "tls": tlsFromQuery(q, server, true)}
	setString(out, "congestion_control", first(q, "congestion_control", "congestion-control"))
	setString(out, "udp_relay_mode", first(q, "udp_relay_mode", "udp-relay-mode"))
	if queryBool(first(q, "zero_rtt_handshake", "zero-rtt-handshake")) {
		out["zero_rtt_handshake"] = true
	}
	return out, nil
}

func parseAnyTLSLink(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	password := userName(u)
	if password == "" {
		return nil, fmt.Errorf("anytls link is missing password")
	}
	return map[string]any{"type": "anytls", "server": server, "server_port": port, "password": password, "tls": tlsFromQuery(u.Query(), server, true)}, nil
}

func parseProxyLink(u *url.URL) (map[string]any, error) {
	server, port, err := endpoint(u)
	if err != nil {
		return nil, err
	}
	typeName := strings.ToLower(u.Scheme)
	if typeName == "socks5" {
		typeName = "socks"
	}
	out := map[string]any{"type": typeName, "server": server, "server_port": port}
	if u.User != nil {
		setString(out, "username", userName(u))
		if password, ok := u.User.Password(); ok {
			setString(out, "password", password)
		}
	}
	if typeName == "https" {
		out["type"] = "http"
		out["tls"] = tlsFromQuery(u.Query(), server, true)
	}
	return out, nil
}

func parseVMessLink(link string) (map[string]any, error) {
	payload, err := decodeBase64(strings.TrimPrefix(strings.TrimPrefix(link, "vmess://"), "VMESS://"))
	if err != nil {
		return nil, fmt.Errorf("invalid vmess link: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid vmess JSON: %w", err)
	}
	server := stringValue(raw["add"])
	port, err := integerValue(raw["port"])
	if err != nil || server == "" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("vmess link has invalid server or port")
	}
	uuid := stringValue(raw["id"])
	if uuid == "" {
		return nil, fmt.Errorf("vmess link is missing UUID")
	}
	out := map[string]any{"type": "vmess", "server": server, "server_port": port, "uuid": uuid}
	security := stringValue(raw["scy"])
	if security == "" {
		security = "auto"
	}
	out["security"] = security
	if alterID, err := integerValue(raw["aid"]); err == nil && alterID != 0 {
		out["alter_id"] = alterID
	}
	q := url.Values{}
	q.Set("security", stringValue(raw["tls"]))
	q.Set("sni", stringValue(raw["sni"]))
	q.Set("fp", stringValue(raw["fp"]))
	q.Set("type", stringValue(raw["net"]))
	q.Set("host", stringValue(raw["host"]))
	q.Set("path", stringValue(raw["path"]))
	if alpn := stringValue(raw["alpn"]); alpn != "" {
		q.Set("alpn", alpn)
	}
	if tls := tlsFromQuery(q, server, false); tls != nil {
		out["tls"] = tls
	}
	if transport := v2rayTransport(q); transport != nil {
		out["transport"] = transport
	}
	return out, nil
}

func parseShadowsocksLink(link string) (map[string]any, error) {
	raw := strings.TrimPrefix(strings.TrimPrefix(link, "ss://"), "SS://")
	if index := strings.IndexByte(raw, '#'); index >= 0 {
		raw = raw[:index]
	}
	u, err := url.Parse("ss://" + raw)
	if err == nil && u.Hostname() != "" && u.User != nil {
		credentials := u.User.Username()
		if decoded, decodeErr := decodeBase64(credentials); decodeErr == nil {
			credentials = string(decoded)
		}
		return shadowsocksOutbound(credentials, u.Hostname(), u.Port())
	}
	decoded, decodeErr := decodeBase64(raw)
	if decodeErr != nil {
		return nil, fmt.Errorf("invalid shadowsocks link: %w", decodeErr)
	}
	credentialsAndEndpoint := string(decoded)
	at := strings.LastIndexByte(credentialsAndEndpoint, '@')
	if at < 0 {
		return nil, fmt.Errorf("invalid shadowsocks link")
	}
	endpointURL, parseErr := url.Parse("ss://" + credentialsAndEndpoint[at+1:])
	if parseErr != nil {
		return nil, fmt.Errorf("invalid shadowsocks endpoint: %w", parseErr)
	}
	return shadowsocksOutbound(credentialsAndEndpoint[:at], endpointURL.Hostname(), endpointURL.Port())
}

func shadowsocksOutbound(credentials, server, portText string) (map[string]any, error) {
	separator := strings.IndexByte(credentials, ':')
	port, err := strconv.Atoi(portText)
	if separator <= 0 || server == "" || err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("shadowsocks link has invalid credentials or endpoint")
	}
	return map[string]any{"type": "shadowsocks", "server": server, "server_port": port, "method": credentials[:separator], "password": credentials[separator+1:]}, nil
}

func endpoint(u *url.URL) (string, int, error) {
	server := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if server == "" || err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("connection link has invalid server or port")
	}
	return server, port, nil
}

func tlsFromQuery(q url.Values, defaultServerName string, force bool) map[string]any {
	security := strings.ToLower(first(q, "security", "tls"))
	enabled := force || security == "tls" || security == "reality" || queryBool(security)
	if !enabled {
		return nil
	}
	tls := map[string]any{"enabled": true}
	serverName := first(q, "sni", "serverName", "peer")
	if serverName == "" {
		serverName = defaultServerName
	}
	setString(tls, "server_name", serverName)
	if queryBool(first(q, "insecure", "allowInsecure", "allow_insecure")) {
		tls["insecure"] = true
	}
	if alpn := splitList(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint := first(q, "fp", "fingerprint"); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	publicKey := first(q, "pbk", "publicKey", "public_key")
	if security == "reality" || publicKey != "" {
		tls["reality"] = map[string]any{"enabled": true, "public_key": publicKey, "short_id": first(q, "sid", "shortId", "short_id")}
	}
	return tls
}

func v2rayTransport(q url.Values) map[string]any {
	typeName := strings.ToLower(first(q, "type", "network"))
	switch typeName {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws"}
		setString(transport, "path", q.Get("path"))
		if host := q.Get("host"); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		setString(transport, "service_name", first(q, "serviceName", "service_name", "path"))
		return transport
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		setString(transport, "path", q.Get("path"))
		if host := splitList(q.Get("host")); len(host) > 0 {
			transport["host"] = host
		}
		return transport
	case "httpupgrade", "http-upgrade":
		transport := map[string]any{"type": "httpupgrade"}
		setString(transport, "host", q.Get("host"))
		setString(transport, "path", q.Get("path"))
		return transport
	case "quic":
		return map[string]any{"type": "quic"}
	default:
		return nil
	}
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func first(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := values.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func userName(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	return u.User.Username()
}

func setString(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}

func setNumber(target map[string]any, key, value string) {
	if number, err := strconv.Atoi(value); err == nil && number > 0 {
		target[key] = number
	}
}

func queryBool(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on", "tls":
		return true
	default:
		return false
	}
}

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func integerValue(value any) (int, error) {
	return strconv.Atoi(stringValue(value))
}

// summariseOutbound достаёт из готового sing-box outbound то, что можно
// показать человеку: порт, вид защиты, SNI и вид транспорта. Секретов здесь
// нет — ни uuid, ни паролей, ни ключей Reality; всё перечисленное и так
// видно любому, кто смотрит на линию.
func summariseOutbound(outbound map[string]any) (port int, security, sni, network string) {
	switch value := outbound["server_port"].(type) {
	case int:
		port = value
	case float64:
		port = int(value)
	}

	if tls, ok := outbound["tls"].(map[string]any); ok {
		if enabled, _ := tls["enabled"].(bool); enabled {
			security = "tls"
			if reality, ok := tls["reality"].(map[string]any); ok {
				if on, _ := reality["enabled"].(bool); on {
					security = "reality"
				}
			}
		}
		if name, ok := tls["server_name"].(string); ok {
			sni = name
		}
	}

	// Отсутствие секции transport в sing-box означает обычный TCP.
	network = "tcp"
	if transport, ok := outbound["transport"].(map[string]any); ok {
		if name, ok := transport["type"].(string); ok && name != "" {
			network = name
		}
	}

	return port, security, sni, network
}
