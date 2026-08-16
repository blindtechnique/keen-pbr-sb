package transport

import "testing"

// The digest the C++ subscription importer compares against. Both halves of
// that comparison derive an identity from a share link, and the rule has to be
// the same one on both sides or the check silently never matches.
func TestLinkFingerprintDropsTheProvidersLabel(t *testing.T) {
	base := "vless://u@a.example:443?security=tls"
	labelled := base + "#Netherlands%2001"
	relabelled := base + "#NL-2"

	if LinkFingerprint(base) != LinkFingerprint(labelled) {
		t.Fatalf("a label must not change the identity")
	}
	if LinkFingerprint(labelled) != LinkFingerprint(relabelled) {
		t.Fatalf("two labels for one connection must agree")
	}
}

func TestLinkFingerprintSeparatesDifferentConnections(t *testing.T) {
	first := LinkFingerprint("vless://u@a.example:443#NL")
	second := LinkFingerprint("vless://u@b.example:443#NL")
	third := LinkFingerprint("vless://v@a.example:443#NL")

	if first == second || first == third || second == third {
		t.Fatalf("host and credential must both reach the digest")
	}
}

func TestLinkFingerprintDoesNotDiscloseTheLink(t *testing.T) {
	const secret = "11111111-1111-1111-1111-111111111111"
	digest := LinkFingerprint("vless://" + secret + "@a.example:443#NL")

	if len(digest) != 64 {
		t.Fatalf("expected a sha256 hex digest, got %q", digest)
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			t.Fatalf("digest is not lowercase hex: %q", digest)
		}
	}
}

func TestLinkFingerprintIsEmptyWithoutALink(t *testing.T) {
	// A transport built from outbound_json has no share link, and a
	// subscription - which is a list of links - can never collide with it.
	for _, value := range []string{"", "   ", "#only-a-fragment"} {
		if got := LinkFingerprint(value); got != "" {
			t.Fatalf("LinkFingerprint(%q) = %q, want empty", value, got)
		}
	}
}

func TestValidateTransportSpecRefusesASuppliedFingerprint(t *testing.T) {
	spec := TransportSpec{
		Tag:             "example",
		Interface:       "tun-example",
		Type:            "sing-box",
		LinkFingerprint: "00",
	}
	if err := ValidateTransportSpec(spec); err == nil {
		t.Fatalf("a caller must not be able to assert an identity")
	}
	spec.LinkFingerprint = ""
	if err := ValidateTransportSpec(spec); err != nil {
		t.Fatalf("an ordinary spec must still validate: %v", err)
	}
}
