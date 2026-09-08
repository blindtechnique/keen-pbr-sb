package transport

import "testing"

func TestAllocateNewTunAddressesPreservesExistingAndExplicitChoices(t *testing.T) {
	existing := []TransportSpec{{Tag: "node_1", Type: "sing-box"}}
	additions := []TransportSpec{
		{Tag: "node_171", Type: "sing-box"},
		{Tag: "manual", Type: "sing-box", TunAddress: "172.19.57.153/30"},
		{Tag: "native", Type: "native", Interface: "nwg5"},
	}
	got, err := AllocateNewTunAddresses(existing, additions)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].TunAddress != "172.19.57.157/30" {
		t.Fatalf("expected first vacant slot after implicit+explicit occupants: %#v", got)
	}
	if got[1].TunAddress != additions[1].TunAddress || got[2].TunAddress != "" || existing[0].TunAddress != "" || additions[0].TunAddress != "" {
		t.Fatal("allocation modified explicit, native or input specs")
	}
	if err := ValidateUniqueTunAddresses(append(existing, got...)); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateNewTunAddressesRejectsOnlyExplicitCollisions(t *testing.T) {
	_, err := AllocateNewTunAddresses([]TransportSpec{{Tag: "node_1", Type: "sing-box"}}, []TransportSpec{{Tag: "manual", Type: "sing-box", TunAddress: "172.19.57.150/30"}})
	if err == nil {
		t.Fatal("explicit overlapping subnet must not be silently moved")
	}
}

func TestAllocateNewTunAddressesFeedSharedRuntimeConfig(t *testing.T) {
	specs, err := AllocateNewTunAddresses(nil, []TransportSpec{
		sharedConfigSpec("node_1", "vless1", "one.example"),
		sharedConfigSpec("node_171", "vless2", "two.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := BuildSharedSingBoxConfig(specs)
	if err != nil {
		t.Fatalf("allocated subscription cannot run in shared mode: %v", err)
	}
	want := map[string]string{"vless1": "172.19.57.149/30", "vless2": "172.19.57.153/30"}
	for _, raw := range shared["inbounds"].([]any) {
		inbound := raw.(map[string]any)
		iface := inbound["interface_name"].(string)
		addresses := inbound["address"].([]string)
		if len(addresses) != 1 || addresses[0] != want[iface] {
			t.Fatalf("runtime lost allocated address for %s: %#v", iface, addresses)
		}
		delete(want, iface)
	}
	if len(want) != 0 {
		t.Fatal("shared config omitted an allocated subscription member")
	}
}
