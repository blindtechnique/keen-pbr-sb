import { postTransportGeo } from "@/api/generated/keen-api"
import type { TransportSpec } from "@/api/generated/model"
import { resolveNativeWireGuardImportLocation } from "@/lib/native-wireguard-import-geo"

/** Country lookup may finish after the editor saves a newer transport. */
export async function persistNativeWireGuardImportCountry(
  transport: TransportSpec,
  endpointHost: string
): Promise<boolean> {
  if (
    transport.type !== "native" ||
    transport.geo_mode !== "auto" ||
    !transport.interface
  ) {
    return false
  }
  const location = await resolveNativeWireGuardImportLocation(endpointHost)
  if (!location) return false
  // This endpoint merges only the country into the current auto-mode native
  // definition. It does not replay a captured alias, mode, or runtime fields.
  const response = await postTransportGeo({
    tag: transport.tag,
    expected_interface: transport.interface,
    country_code: location.country_code,
    country: location.country,
  })
  return response.status === 200 && response.data.updated
}
