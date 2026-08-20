import { describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"

type Operation = {
  tags?: string[]
  operationId?: string
  requestBody?: unknown
  parameters?: Array<{
    name?: string
    in?: string
    required?: boolean
    schema?: { enum?: string[] }
  }>
  responses?: Record<string, unknown>
}

type ObjectSchema = {
  additionalProperties?: boolean
  required?: string[]
  properties?: Record<string, unknown>
  enum?: string[]
}

type OpenApiDocument = {
  paths: Record<string, { post?: Operation }>
  components: { schemas: Record<string, ObjectSchema> }
}

const repoRoot = resolve(import.meta.dir, "../../..")
const specPath = resolve(repoRoot, "docs/openapi.yaml")
const generatedRoot = resolve(repoRoot, "frontend/src/api/generated")
const manualMutationTag = "Native manual mutation transport"
const manualMutationPaths = [
  "/api/system/ndms/interfaces/remove",
  "/api/system/ndms/interfaces/remove/recovery/retry",
  "/api/system/ndms/interfaces/import/recovery/retry",
] as const

const loadSpec = async () =>
  Bun.YAML.parse(await Bun.file(specPath).text()) as OpenApiDocument

describe("native mutation OpenAPI generation boundary", () => {
  test("tags exactly the three one-shot operations for client exclusion", async () => {
    const spec = await loadSpec()
    const taggedPaths = Object.entries(spec.paths)
      .filter(([, path]) => path.post?.tags?.includes(manualMutationTag))
      .map(([path]) => path)
      .sort()

    expect(taggedPaths).toEqual([...manualMutationPaths].sort())
    for (const path of manualMutationPaths) {
      expect(spec.paths[path]?.post?.tags).toEqual([manualMutationTag])
    }
  })

  test("keeps recovery bodyless and delete request exact", async () => {
    const spec = await loadSpec()
    expect(
      spec.paths[manualMutationPaths[1]]?.post?.requestBody
    ).toBeUndefined()
    expect(
      spec.paths[manualMutationPaths[2]]?.post?.requestBody
    ).toBeUndefined()

    const request = spec.components.schemas.NdmsNativeDeleteRequest
    expect(request.additionalProperties).toBeFalse()
    expect(request.required?.sort()).toEqual(
      ["confirm_label", "expected_ownership_revision", "interface_name"].sort()
    )
    expect(Object.keys(request.properties ?? {}).sort()).toEqual(
      ["confirm_label", "expected_ownership_revision", "interface_name"].sort()
    )

    const recovery = spec.paths[manualMutationPaths[2]]?.post
    expect(recovery?.parameters).toEqual([
      expect.objectContaining({
        name: "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance",
        in: "header",
        required: false,
        schema: { type: "string", enum: ["owner-accepted"] },
      }),
    ])
    expect(recovery?.responses).toHaveProperty("428")
  })

  test("publishes redacted schemas without an internal transaction id", async () => {
    const spec = await loadSpec()
    for (const schemaName of [
      "NdmsNativeImportResponse",
      "NdmsNativeImportRecoveryResponse",
      "NdmsNativeDeleteResponse",
    ]) {
      expect(
        Object.hasOwn(
          spec.components.schemas[schemaName]?.properties ?? {},
          "transaction_id"
        )
      ).toBeFalse()
    }

    expect(
      spec.components.schemas.NdmsNativeImportRecoveryResponse.required
    ).toEqual(
      expect.arrayContaining([
        "ndms_import_request_dispatched",
        "ndms_delete_dispatched",
        "system_configuration_save_performed",
        "external_ndms_writer_race_excluded",
        "external_ndms_writer_race_accepted",
        "delete_perform_started",
        "request_may_have_been_dispatched",
        "wal_may_require_recovery",
        "ownership_published",
        "rollback_snapshot_retired",
        "wal_removed",
      ])
    )

    expect(
      spec.components.schemas.NdmsNativeImportRecoveryStatus.enum
    ).toContain("recovery_required")
    expect(spec.components.schemas.NdmsNativeImportRecoveryStop.enum).toEqual(
      expect.arrayContaining([
        "external_writer_race_not_accepted",
        "snapshot_not_exact",
        "recovery_admission_failed",
        "delete_guard_rejected",
        "delete_transport_ambiguous",
        "snapshot_retirement_failed",
      ])
    )
    expect(
      spec.components.schemas.NdmsNativeImportRecoveryResponse.properties
    ).toEqual(
      expect.objectContaining({
        recovery_admission_state: expect.any(Object),
        recovery_dispatch_state: expect.any(Object),
        recovery_failed_step: expect.any(Object),
        delete_transport_outcome: {
          $ref: "#/components/schemas/NdmsNativeDeleteTransportOutcome",
        },
      })
    )
  })

  test("generates models but no callable client for manual mutations", () => {
    for (const model of [
      "ndmsNativeDeleteRequest.ts",
      "ndmsNativeDeleteResponse.ts",
      "ndmsNativeImportRecoveryResponse.ts",
    ]) {
      expect(existsSync(resolve(generatedRoot, "model", model))).toBeTrue()
    }

    const client = readFileSync(resolve(generatedRoot, "keen-api.ts"), "utf8")
    for (const path of manualMutationPaths) {
      expect(client).not.toContain(path)
    }
  })
})
