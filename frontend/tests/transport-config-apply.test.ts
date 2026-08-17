import { describe, expect, spyOn, test } from "bun:test"

import {
  createLinkedTransportApplyRequest,
  postTransportConfigApply,
} from "../src/api/mutations"
import {
  TransportSpecType,
  type TransportSpec,
} from "../src/api/generated/model"

const transport: TransportSpec = {
  tag: "tr_primary",
  display_name: "  Основной VLESS  ",
  type: TransportSpecType["sing-box"],
  interface: "kpbrprimary",
  auto_start: true,
  link: "vless://example",
}

describe("atomic transport creation request", () => {
  test("requests the linked interface outbound in the same operation", () => {
    expect(createLinkedTransportApplyRequest(transport)).toEqual({
      operation: "create",
      transport,
      linked_outbound: {
        mode: "ensure",
        display_name: "Основной VLESS",
      },
    })
  })

  test("does not synthesize a visible name from a technical tag", () => {
    expect(
      createLinkedTransportApplyRequest({
        ...transport,
        display_name: "   ",
      }).linked_outbound
    ).toEqual({
      mode: "ensure",
      display_name: undefined,
    })
  })

  test("sends one authoritative request for both objects", async () => {
    const request = createLinkedTransportApplyRequest(transport)
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "applied" }), {
        headers: { "content-type": "application/json" },
        status: 200,
      })
    )

    try {
      const response = await postTransportConfigApply(request)

      expect(response.data).toEqual({ status: "applied" })
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(fetchSpy).toHaveBeenCalledWith(
        "/api/transports/config/apply",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(request),
        })
      )
    } finally {
      fetchSpy.mockRestore()
    }
  })
})
