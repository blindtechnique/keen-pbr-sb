"use strict";

const { readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");
const yaml = require("../frontend/node_modules/js-yaml");

const referencePrefix = "#/components/schemas/";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Derive wire keys from the configuration graph only. Walking arbitrary JSON
// objects would also follow example payloads, which are data, not schema.
function collectConfigKnownFields(schemas) {
  if (!isRecord(schemas) || !Object.hasOwn(schemas, "ConfigObject")) {
    throw new Error("Missing ConfigObject schema");
  }
  const reachable = new Set();

  function referencedName(reference) {
    if (typeof reference !== "string" || !reference.startsWith(referencePrefix)) {
      throw new Error(`Unsupported configuration schema reference: ${reference}`);
    }
    const name = reference.slice(referencePrefix.length).replace(/~1/g, "/").replace(/~0/g, "~");
    if (!Object.hasOwn(schemas, name)) throw new Error(`Missing configuration schema: ${name}`);
    return name;
  }

  function visitSchema(schema) {
    if (!isRecord(schema)) return;
    if (Object.hasOwn(schema, "$ref")) visitNamed(referencedName(schema.$ref));
    if (isRecord(schema.properties)) Object.values(schema.properties).forEach(visitSchema);
    visitSchema(schema.items);
    visitSchema(schema.additionalProperties);
    for (const composition of ["allOf", "oneOf", "anyOf"]) {
      if (Array.isArray(schema[composition])) schema[composition].forEach(visitSchema);
    }
  }

  function visitNamed(name) {
    if (reachable.has(name)) return;
    reachable.add(name);
    visitSchema(schemas[name]);
  }

  // Composed objects and named aliases share their declared object keys.
  // Nested properties are separate objects and must not leak into this list.
  function ownObjectKeys(schema, seen = new Set()) {
    if (!isRecord(schema)) return { object: false, keys: new Set() };
    const result = {
      object: schema.type === "object" || isRecord(schema.properties),
      keys: new Set(Object.keys(schema.properties ?? {})),
    };
    function merge(part) {
      result.object ||= part.object;
      for (const key of part.keys) result.keys.add(key);
    }
    if (Object.hasOwn(schema, "$ref")) {
      const name = referencedName(schema.$ref);
      if (!seen.has(name)) merge(ownObjectKeys(schemas[name], new Set([...seen, name])));
    }
    for (const composition of ["allOf", "oneOf", "anyOf"]) {
      for (const part of schema[composition] ?? []) merge(ownObjectKeys(part, seen));
    }
    return result;
  }

  visitNamed("ConfigObject");
  const result = {};
  for (const name of [...reachable].sort()) {
    const fields = ownObjectKeys(schemas[name], new Set([name]));
    if (fields.object) result[name] = [...fields.keys].sort();
  }
  return result;
}

function renderConfigKnownFields(schemas) {
  return "// Generated from docs/openapi.yaml; do not edit by hand.\n" +
    "// Regenerate with: bun run config:known-fields:generate (from frontend/).\n\n" +
    `export const configKnownFields = ${JSON.stringify(collectConfigKnownFields(schemas), null, 2)} as const\n`;
}

function updateGeneratedFile(path, content, checkOnly) {
  let current;
  try {
    current = readFileSync(path, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  // Git may check out this generated file with CRLF on Windows.
  if (current?.replace(/\r\n/g, "\n") === content) return true;
  if (checkOnly) return false;
  writeFileSync(path, content);
  return true;
}

module.exports = { collectConfigKnownFields, renderConfigKnownFields, updateGeneratedFile };

if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    if (args.some((arg) => arg !== "--check")) {
      throw new Error("Usage: generate_config_known_fields.cjs [--check]");
    }
    const root = resolve(__dirname, "..");
    const schemas = yaml.load(readFileSync(resolve(root, "docs/openapi.yaml"), "utf8"))?.components?.schemas;
    const output = resolve(root, "frontend/src/lib/config-known-fields.generated.ts");
    if (!updateGeneratedFile(output, renderConfigKnownFields(schemas), args.includes("--check"))) {
      throw new Error("Configuration known-field metadata is stale; run bun run config:known-fields:generate in frontend/");
    }
    console.log(`Configuration known-field metadata ${args.includes("--check") ? "verified" : "generated"}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
