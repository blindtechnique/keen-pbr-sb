package transport

import (
	"fmt"
	"hash/fnv"
	"net"
)

const generatedTunSubnetCount = 1 << 14

func generatedTunSlot(tag string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(tag))
	return hash.Sum32() % generatedTunSubnetCount
}

func generatedTunAddress(slot uint32) string {
	return fmt.Sprintf("172.19.%d.%d/30", slot>>6, (slot&63)*4+1)
}

// AllocateNewTunAddresses leaves every existing implicit/explicit address
// untouched. Only new generated assignments probe for a vacant /30 and are
// persisted in the returned specs, so deletion/reordering cannot move them.
func AllocateNewTunAddresses(existing, additions []TransportSpec) ([]TransportSpec, error) {
	assigned := make([]TransportSpec, len(additions))
	for index, spec := range additions {
		assigned[index] = cloneTransportSpec(spec)
	}
	used := make(map[string]string)
	reserve := func(spec TransportSpec) error {
		if !isManagedSingBoxSpec(spec) {
			return nil
		}
		address, err := tunAddressForSpec(spec)
		if err != nil {
			return fmt.Errorf("transport %q: %w", spec.Tag, err)
		}
		_, network, _ := net.ParseCIDR(address)
		if previous, exists := used[network.String()]; exists {
			return fmt.Errorf("transports %q and %q use the same TUN subnet %s; set tun_address manually", previous, spec.Tag, network)
		}
		used[network.String()] = spec.Tag
		return nil
	}
	for _, spec := range existing {
		if err := reserve(spec); err != nil {
			return nil, err
		}
	}
	// Honor explicit addresses even when they occur after generated entries.
	for _, spec := range assigned {
		if spec.TunAddress != "" {
			if err := reserve(spec); err != nil {
				return nil, err
			}
		}
	}
	for index := range assigned {
		spec := &assigned[index]
		if !isManagedSingBoxSpec(*spec) || spec.TunAddress != "" {
			continue
		}
		first := generatedTunSlot(spec.Tag)
		for offset := uint32(0); offset < generatedTunSubnetCount; offset++ {
			address := generatedTunAddress((first + offset) % generatedTunSubnetCount)
			_, network, _ := net.ParseCIDR(address)
			if _, occupied := used[network.String()]; occupied {
				continue
			}
			spec.TunAddress = address
			used[network.String()] = spec.Tag
			break
		}
		if spec.TunAddress == "" {
			return nil, fmt.Errorf("no free generated TUN subnet for transport %q", spec.Tag)
		}
	}
	return assigned, nil
}
