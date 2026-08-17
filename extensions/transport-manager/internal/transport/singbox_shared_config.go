package transport

import (
	"fmt"
	"sort"
)

// BuildSharedSingBoxConfig builds one deterministic sing-box configuration
// for all managed proxy transports. It is intentionally side-effect free:
// process ownership, validation with the sing-box binary and atomic runtime
// switching belong to the shared lifecycle coordinator.
//
// Native transports are ignored so callers may pass the complete transport
// inventory. At least one managed sing-box transport is required.
func BuildSharedSingBoxConfig(specs []TransportSpec) (map[string]any, error) {
	managed := make([]TransportSpec, 0, len(specs))
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			managed = append(managed, spec)
		}
	}
	if len(managed) == 0 {
		return nil, fmt.Errorf("shared sing-box config requires at least one managed proxy transport")
	}

	sort.Slice(managed, func(left, right int) bool {
		return managed[left].Tag < managed[right].Tag
	})
	if err := validateSharedSingBoxSpecs(managed); err != nil {
		return nil, err
	}

	inbounds := make([]any, 0, len(managed))
	outbounds := make([]any, 0, len(managed)+1)
	rules := make([]any, 0, len(managed))
	// A route-wide local resolver covers imported dial fields and the direct
	// fallback. Transports with explicit bootstrap DNS override it below, so
	// their server lookup remains isolated from the router's routed DNS policy.
	dnsServers := []any{systemLocalDNSServer()}

	for _, spec := range managed {
		inboundTag := sharedInboundTag(spec.Tag)
		outboundTag := sharedOutboundTag(spec.Tag)

		tun, err := tunInboundFromSpec(spec, inboundTag)
		if err != nil {
			return nil, fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		outbound, err := outboundFromSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		outbound["tag"] = outboundTag

		if len(spec.BootstrapDNS) > 0 {
			servers, err := buildBootstrapDNSServers(spec.BootstrapDNS, func(index int) string {
				return sharedBootstrapDNSTag(spec.Tag, index)
			})
			if err != nil {
				return nil, fmt.Errorf("transport %q: %w", spec.Tag, err)
			}
			dnsServers = append(dnsServers, servers...)
			// Per-outbound resolvers keep different proxy server hostnames
			// isolated even though all proxies share one sing-box process.
			outbound["domain_resolver"] = domainResolver(sharedBootstrapDNSTag(spec.Tag, 0))
		}

		inbounds = append(inbounds, tun)
		outbounds = append(outbounds, outbound)
		rules = append(rules, map[string]any{
			"inbound":  []string{inboundTag},
			"action":   "route",
			"outbound": outboundTag,
		})
	}

	outbounds = append(outbounds, map[string]any{
		"type": "direct",
		"tag":  "direct-out",
	})
	config := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface":   true,
			"rules":                   rules,
			"final":                   "direct-out",
			"default_domain_resolver": domainResolver(systemLocalDNSTag),
		},
		"dns": map[string]any{"servers": dnsServers},
	}
	return config, nil
}

func validateSharedSingBoxSpecs(specs []TransportSpec) error {
	if err := ValidateUniqueTunAddresses(specs); err != nil {
		return err
	}
	tags := make(map[string]struct{}, len(specs))
	interfaces := make(map[string]string, len(specs))
	for _, spec := range specs {
		if err := ValidateTransportSpec(spec); err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		if _, exists := tags[spec.Tag]; exists {
			return fmt.Errorf("duplicate shared sing-box transport tag %q", spec.Tag)
		}
		tags[spec.Tag] = struct{}{}
		if previous, exists := interfaces[spec.Interface]; exists {
			return fmt.Errorf("transports %q and %q use the same TUN interface %q", previous, spec.Tag, spec.Interface)
		}
		interfaces[spec.Interface] = spec.Tag
	}
	return nil
}

func tunInboundFromSpec(spec TransportSpec, tag string) (map[string]any, error) {
	address, err := tunAddressForSpec(spec)
	if err != nil {
		return nil, err
	}
	mtu := spec.MTU
	if mtu == 0 && spec.VLESS != nil {
		mtu = spec.VLESS.MTU
	}
	if mtu == 0 {
		mtu = 1420
	}
	return map[string]any{
		"type":           "tun",
		"tag":            tag,
		"interface_name": spec.Interface,
		"address":        []string{address},
		"mtu":            mtu,
		"stack":          "gvisor",
		"auto_route":     false,
		"strict_route":   false,
	}, nil
}

func sharedInboundTag(tag string) string {
	return "tun-in-" + tag
}

func sharedOutboundTag(tag string) string {
	return "proxy-out-" + tag
}

func sharedBootstrapDNSTag(tag string, index int) string {
	return fmt.Sprintf("bootstrap-%s-%d", tag, index+1)
}
