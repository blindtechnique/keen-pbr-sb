#!/usr/bin/env bun

// Cross-platform equivalent of generate_api_types.sh for environments where
// Bash/npx are unavailable. The generated output is intentionally identical.
import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import yaml from "../frontend/node_modules/js-yaml/index.js"

const scriptDir = dirname(fileURLToPath(import.meta.url))
const root = resolve(scriptDir, "..")
const schemas = yaml.load(readFileSync(join(root, "docs/openapi.yaml"), "utf8"))
  .components.schemas

function clean(value) {
  if (!value || typeof value !== "object") return
  if (Array.isArray(value)) {
    value.forEach(clean)
    return
  }
  delete value.discriminator
  delete value.example
  delete value.description
  Object.values(value).forEach(clean)
}

function rewriteRefs(value) {
  if (!value || typeof value !== "object") return
  if (Array.isArray(value)) {
    value.forEach(rewriteRefs)
    return
  }
  if (value.$ref) {
    value.$ref = value.$ref.replace("#/components/schemas/", "#/$defs/")
  }
  Object.values(value).forEach(rewriteRefs)
}

clean(schemas)
rewriteRefs(schemas)

const rootProperties = Object.fromEntries(
  Object.keys(schemas).map((name) => [name, { $ref: `#/$defs/${name}` }])
)
const schema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  $defs: schemas,
  type: "object",
  properties: rootProperties,
}

const temporaryDirectory = mkdtempSync(join(tmpdir(), "keen-pbr-types-"))
const schemaPath = join(temporaryDirectory, "schema.json")
const typesPath = join(temporaryDirectory, "api_types.hpp")

try {
  writeFileSync(schemaPath, JSON.stringify(schema, null, 2))
  execFileSync(
    process.execPath,
    [
      "x",
      "quicktype",
      "--lang",
      "cpp",
      "--src",
      schemaPath,
      "--src-lang",
      "schema",
      "--namespace",
      "keen_pbr3::api",
      "--no-boost",
      "--code-format",
      "with-struct",
      "-o",
      typesPath,
    ],
    { stdio: "inherit" }
  )

  let content = readFileSync(typesPath, "utf8")
  content = content.replace('#include "json.hpp"', "#include <nlohmann/json.hpp>")
  content = content.replace(
    "#include <optional>",
    "#include <cstdint>\n#include <map>\n#include <optional>"
  )
  content =
    "// Generated from docs/openapi.yaml via build_scripts/generate_api_types.sh\n" +
    '// Run "make generate" to regenerate (requires Node.js).\n\n' +
    content
  writeFileSync(join(root, "src/api/generated/api_types.hpp"), content)
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true })
}
