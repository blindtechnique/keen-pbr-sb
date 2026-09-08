import { describe, expect, test } from "bun:test"
import { preserveConfigFields } from "./preserve_config_fields.cjs"

type Field = { type: string; member: string; key?: string; initial?: string }

function struct(name: string, fields: Field[]) {
  return `    struct ${name} {\n${fields.map((field) =>
    `        ${field.type} ${field.member}${field.initial === undefined ? "" : ` = ${field.initial}`};`
  ).join("\n")}\n    };\n\n` +
    `    inline void from_json(const json & j, ${name}& x) {\n${fields.map((field) =>
      `        x.${field.member} = j.at(${JSON.stringify(field.key ?? field.member)}).get<${field.type}>();`
    ).join("\n")}\n    }\n\n` +
    `    inline void to_json(json & j, const ${name} & x) {\n        j = json::object();\n${fields.map((field) =>
      `        j[${JSON.stringify(field.key ?? field.member)}] = x.${field.member};`
    ).join("\n")}\n    }\n`
}

const child = struct("Child", [{ type: "std::optional<bool>", member: "enabled" }])
const root = struct("ConfigObject", [
  { type: "std::optional<std::map<std::string, std::vector<Child>>>", member: "groups" },
  { type: "int64_t", member: "schema_version", initial: "2" },
])
const unrelated = struct("AuthCredentials", [{ type: "std::string", member: "password" }])
const fixture = child + root + unrelated

describe("config-only generated field preservation", () => {
  test("walks nested optional/map/vector structs without changing unrelated DTOs", () => {
    const generated = preserveConfigFields(fixture)
    expect(generated.match(/json _config_unknown_fields = nullptr;/g)).toHaveLength(2)
    expect(generated).toContain(unrelated)
    expect(generated).not.toContain("const AuthCredentials & x);")
  })

  test("appends metadata after existing aggregate fields and leaves schema defaults", () => {
    const generated = preserveConfigFields(fixture)
    expect(generated).toContain("int64_t schema_version = 2;\n        // Opaque fields")
    expect(generated).toContain("std::optional<bool> enabled;\n        // Opaque fields")
  })

  test("resets reused extras and captures only unrecognized JSON keys", () => {
    const generated = preserveConfigFields(fixture)
    expect(generated).toContain("ConfigObject& x) {\n        x._config_unknown_fields = nullptr;")
    expect(generated).toContain('if (it.key() == "groups" || it.key() == "schema_version") continue;')
    expect(generated).toContain("if (x._config_unknown_fields.is_null()) x._config_unknown_fields = json::object();")
    expect(generated).not.toContain("x._config_unknown_fields = j;")
  })

  test("known serialized fields override extras including optional resets", () => {
    const generated = preserveConfigFields(fixture)
    expect(generated).toContain('j = x._config_unknown_fields.is_object() ? x._config_unknown_fields : json::object();\n        j["enabled"] = x.enabled;')
  })

  test("uses serialized JSON names instead of assuming member names", () => {
    const generated = preserveConfigFields(struct("ConfigObject", [
      { type: "std::optional<bool>", member: "enabled_flag", key: "enabled-flag" },
    ]))
    expect(generated).toContain('if (it.key() == "enabled-flag") continue;')
    expect(generated).toContain('if (auto it = j.find("enabled-flag"); it != j.end())')
    expect(generated).toContain("prune_config_json_for_persistence(*it, x.enabled_flag)")
  })

  test("prunes only known fields and leaves raw JSON values opaque", () => {
    const generated = preserveConfigFields(fixture)
    const helpers = generated.slice(generated.indexOf("// Remove absent known values"))
    expect(helpers).not.toContain("_config_unknown_fields")
    expect(helpers).not.toContain("for (auto it = j.begin()")
    expect(helpers).toContain("const json &) {\n        return false;")
    expect(helpers).toContain("j[i], x[i]")
    expect(helpers).toContain("j.find(entry.first)")
  })

  test("declares concrete and container overloads before dependent definitions", () => {
    const generated = preserveConfigFields(fixture)
    expect(generated.indexOf("const Child & x);")).toBeLessThan(generated.indexOf("template <typename T>"))
    expect(generated.indexOf("const std::map<std::string, T> & x);")).toBeLessThan(
      generated.indexOf("return !x || prune_config_json_for_persistence"))
  })

  test("accepts reachable enums without adding object metadata to them", () => {
    const generated = preserveConfigFields("    enum class Mode : int { FIRST, SECOND };\n" +
      struct("ConfigObject", [{ type: "Mode", member: "mode" }]))
    expect(generated.match(/json _config_unknown_fields = nullptr;/g)).toHaveLength(1)
  })

  test("fails clearly on absent root and metadata collisions", () => {
    expect(() => preserveConfigFields(child)).toThrow("missing ConfigObject root")
    expect(() => preserveConfigFields(struct("ConfigObject", [
      { type: "json", member: "_config_unknown_fields" },
    ]))).toThrow("reserved member collision")
    expect(() => preserveConfigFields(preserveConfigFields(fixture))).toThrow("unsupported member declaration")
  })

  test("fails on a newly reachable unsupported union rather than silently losing its fields", () => {
    expect(() => preserveConfigFields(struct("ConfigObject", [
      { type: "std::variant<bool, Child>", member: "mode" },
    ]) + child)).toThrow("unsupported reachable type std::variant<bool, Child>")
  })

  test("fails clearly when quicktype serialization grammar changes", () => {
    expect(() => preserveConfigFields(fixture.replace('j["groups"] = x.groups;', 'j.emplace("groups", x.groups);')))
      .toThrow("unsupported writer statement")
    expect(() => preserveConfigFields(fixture.replace('        j["groups"] = x.groups;\n', "")))
      .toThrow("writer/member count mismatch")
    expect(() => preserveConfigFields(fixture.replace("inline void from_json(const json & j, ConfigObject& x)", "inline void parse(json j, ConfigObject& x)")))
      .toThrow("expected one from_json")
  })

  test("normalizes platform newlines deterministically", () => {
    expect(preserveConfigFields(fixture.replace(/\n/g, "\r\n"))).toBe(preserveConfigFields(fixture))
  })
})
