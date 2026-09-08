"use strict";

// Config objects must retain fields written by a newer version while ordinary
// typed edits move, replace or remove their containing objects. Keep that data
// on each generated config object, not in a second raw document merged by array
// index. This pass deliberately does not change unrelated request/auth DTOs.
const extensionMember = "_config_unknown_fields";

function preserveConfigFields(input) {
  let content = input.replace(/\r\n/g, "\n");
  const escaped = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const fail = (message) => { throw new Error(`Config field preservation: ${message}`); };
  const structs = new Map();
  for (const match of content.matchAll(/^    struct (\w+) \{\n([\s\S]*?)^    \};/gm)) {
    if (structs.has(match[1])) fail(`duplicate struct ${match[1]}`);
    structs.set(match[1], { name: match[1], body: match[2], original: match[0] });
  }
  if (!structs.has("ConfigObject")) fail("missing ConfigObject root");
  const enums = new Set([...content.matchAll(/^    enum class (\w+)\s*:/gm)].map((match) => match[1]));
  const leaves = new Set(["bool", "int64_t", "double", "std::string", "json", "nlohmann::json"]);
  const reachable = new Map();

  function visitType(type, owner) {
    type = type.trim();
    if (leaves.has(type) || enums.has(type)) return;
    if (structs.has(type)) { visitStruct(type); return; }
    const container = type.match(/^std::(optional|vector)<(.+)>$/);
    if (container) { visitType(container[2], owner); return; }
    const dictionary = type.match(/^std::map<std::string,\s*(.+)>$/);
    if (dictionary) { visitType(dictionary[1], owner); return; }
    fail(`unsupported reachable type ${type} in ${owner}`);
  }

  function functionBody(type, direction) {
    const signature = direction === "from_json"
      ? `inline void from_json\\(const json & j, ${escaped(type)}& x\\)`
      : `inline void to_json\\(json & j, const ${escaped(type)} & x\\)`;
    const matches = [...content.matchAll(new RegExp(`    ${signature} \\{\\n([\\s\\S]*?)^    \\}`, "gm"))];
    if (matches.length !== 1) fail(`expected one ${direction} for ${type}`);
    return { original: matches[0][0], body: matches[0][1] };
  }

  function visitStruct(name) {
    if (reachable.has(name)) return;
    const struct = structs.get(name);
    const fields = [];
    for (const line of struct.body.trimEnd().split("\n")) {
      const match = line.match(/^        (.+?) ([a-z_][a-z0-9_]*)(?: = [^;]+)?;$/);
      if (!match) fail(`unsupported member declaration in ${name}: ${line.trim()}`);
      if (match[2] === extensionMember) fail(`reserved member collision in ${name}`);
      fields.push({ type: match[1], member: match[2] });
    }
    const writer = functionBody(name, "to_json");
    const assignments = new Map();
    const writerLines = writer.body.trimEnd().split("\n");
    if (writerLines.shift() !== "        j = json::object();") fail(`unexpected writer initialization in ${name}`);
    for (const line of writerLines) {
      const match = line.match(/^        j\[("(?:\\.|[^"\\])*")\] = x\.(\w+);$/);
      if (!match || assignments.has(match[2])) fail(`unsupported writer statement in ${name}: ${line.trim()}`);
      assignments.set(match[2], match[1]);
    }
    if (assignments.size !== fields.length) fail(`writer/member count mismatch in ${name}`);
    const reader = functionBody(name, "from_json");
    const readerMembers = reader.body.trimEnd().split("\n").map((line) => {
      const match = line.match(/^        x\.(\w+) = .+;$/);
      if (!match) fail(`unsupported reader statement in ${name}: ${line.trim()}`);
      return match[1];
    });
    if (new Set(readerMembers).size !== fields.length || readerMembers.length !== fields.length) {
      fail(`reader/member count mismatch in ${name}`);
    }
    for (const field of fields) {
      field.key = assignments.get(field.member);
      if (!field.key || !readerMembers.includes(field.member)) fail(`missing reader/writer member ${name}.${field.member}`);
    }
    reachable.set(name, { ...struct, fields, reader, writer });
    for (const field of fields) visitType(field.type, `${name}.${field.member}`);
  }
  visitStruct("ConfigObject");

  for (const struct of reachable.values()) {
    content = content.replace(struct.original, struct.original.replace(
      /\n    \};$/, `\n        // Opaque fields belonging to this object; not an API property.\n        json ${extensionMember} = nullptr;\n    };`));
    const capture = [
      `        x.${extensionMember} = nullptr;`,
      "        if (j.is_object()) {",
      "            for (auto it = j.begin(); it != j.end(); ++it) {",
      `                if (${struct.fields.map((field) => `it.key() == ${field.key}`).join(" || ")}) continue;`,
      `                if (x.${extensionMember}.is_null()) x.${extensionMember} = json::object();`,
      `                x.${extensionMember}[it.key()] = it.value();`,
      "            }",
      "        }",
    ].join("\n") + "\n";
    content = content.replace(struct.reader.original, struct.reader.original.replace("{\n", "{\n" + capture));
    content = content.replace(struct.writer.original, struct.writer.original.replace(
      "        j = json::object();",
      `        j = x.${extensionMember}.is_object() ? x.${extensionMember} : json::object();`));
  }

  // Declare struct overloads before container templates: dependent calls must
  // reach the typed overload even when optional/vector/map wrappers are nested.
  const declarations = [...reachable.keys()].map((name) =>
    `    inline bool prune_config_json_for_persistence(json & j, const ${name} & x);`).join("\n");
  const definitions = [...reachable.values()].map((struct) => {
    const visits = struct.fields.map((field) => [
      `        if (auto it = j.find(${field.key}); it != j.end()) {`,
      `            if (prune_config_json_for_persistence(*it, x.${field.member})) j.erase(it);`,
      "        }",
    ].join("\n")).join("\n");
    return `    inline bool prune_config_json_for_persistence(json & j, const ${struct.name} & x) {\n` +
      "        if (!j.is_object()) return j.is_null();\n" + visits + "\n        return j.empty();\n    }";
  }).join("\n\n");
  content += `
// Remove absent known values for persistent configuration only. Unknown JSON
// payloads are opaque, including their nulls, empty objects and array entries.
namespace keen_pbr3 {
namespace api {
${declarations}

    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const T &) {
        return j.is_null();
    }

    // Raw JSON is an opaque value even when a future config field names it.
    inline bool prune_config_json_for_persistence(json &, const json &) {
        return false;
    }

    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::optional<T> & x);
    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::vector<T> & x);
    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::map<std::string, T> & x);

    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::optional<T> & x) {
        return !x || prune_config_json_for_persistence(j, *x);
    }

    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::vector<T> & x) {
        if (!j.is_array()) return j.is_null();
        for (std::size_t i = 0; i < x.size() && i < j.size(); ++i) {
            (void)prune_config_json_for_persistence(j[i], x[i]);
        }
        return false;
    }

    template <typename T>
    inline bool prune_config_json_for_persistence(json & j, const std::map<std::string, T> & x) {
        if (!j.is_object()) return j.is_null();
        for (const auto & entry : x) {
            if (auto it = j.find(entry.first); it != j.end()) {
                if (prune_config_json_for_persistence(*it, entry.second)) j.erase(it);
            }
        }
        return j.empty();
    }

${definitions}
}
}
`;
  return content;
}

module.exports = { preserveConfigFields };
