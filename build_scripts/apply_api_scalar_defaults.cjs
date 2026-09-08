"use strict";

// QuickType ignores numeric/bool schema defaults in generated struct members.
// Apply only explicit defaults on required scalars; optional fields keep their
// absence semantics. Read the synthetic-root mapping instead of assuming that
// QuickType retains each schema's name (e.g. DaemonConfig becomes Daemon).
function applyApiScalarDefaults(content, definitions) {
  const typeBySchema = new Map();
  const rootReaders = /x\.\w+ = get_stack_optional<([\w:]+)>\(j, "([^"]+)"\);/g;
  for (const match of content.matchAll(rootReaders)) {
    if (Object.hasOwn(definitions, match[2])) typeBySchema.set(match[2], match[1]);
  }
  const escaped = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  for (const [schemaName, schema] of Object.entries(definitions)) {
    for (const propertyName of schema.required ?? []) {
      const property = schema.properties?.[propertyName];
      if (!property || !Object.hasOwn(property, "default")) continue;
      const cppType = { integer: "int64_t", number: "double", boolean: "bool" }[property.type];
      if (!cppType) continue;
      const value = property.default;
      if ((property.type === "boolean" && typeof value !== "boolean") ||
          (property.type !== "boolean" && (typeof value !== "number" || !Number.isFinite(value))) ||
          (property.type === "integer" && !Number.isSafeInteger(value))) {
        throw new Error(`Invalid scalar default for ${schemaName}.${propertyName}`);
      }
      const typeName = typeBySchema.get(schemaName);
      if (!typeName) throw new Error(`Missing generated type for ${schemaName}`);
      const reader = content.match(new RegExp(
        `inline void from_json\\(const json & j, ${escaped(typeName)}& x\\) \\{([\\s\\S]*?)\\n    \\}`));
      const assignment = reader?.[1].match(new RegExp(
        `x\\.(\\w+) = j\\.at\\("${escaped(propertyName)}"\\)\\.get<${cppType}>\\(\\);`));
      if (!assignment) throw new Error(`Missing generated scalar reader for ${schemaName}.${propertyName}`);
      const member = new RegExp(`(\\b${cppType} ${escaped(assignment[1])} = )(?:0|false);`);
      let replaced = false;
      content = content.replace(new RegExp(
        `(struct ${escaped(typeName)} \\{)([\\s\\S]*?)(\\n    \\};)`),
      (_match, start, body, end) => start + body.replace(member, (_field, prefix) => {
        replaced = true;
        return prefix + JSON.stringify(value) + ";";
      }) + end);
      if (!replaced) throw new Error(`Missing generated scalar member for ${schemaName}.${propertyName}`);
    }
  }
  return content;
}

module.exports = { applyApiScalarDefaults };
