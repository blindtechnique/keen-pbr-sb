"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { applyApiScalarDefaults } = require("../apply_api_scalar_defaults.cjs");

const generated = `
    struct Renamed {
        int64_t revision = 0;
        bool enabled = false;
        double interval = 0;
        std::optional<int64_t> optional;
    };
    inline void from_json(const json & j, Renamed& x) {
        x.revision = j.at("revision").get<int64_t>();
        x.enabled = j.at("enabled").get<bool>();
        x.interval = j.at("interval").get<double>();
        x.optional = get_stack_optional<int64_t>(j, "optional");
    }
    x.configuration = get_stack_optional<Renamed>(j, "ConfigurationSchema");
`;
const definitions = {
  ConfigurationSchema: {
    required: ["revision", "enabled", "interval"],
    properties: {
      revision: { type: "integer", default: 7 },
      enabled: { type: "boolean", default: true },
      interval: { type: "number", default: 2.5 },
      optional: { type: "integer", default: 9 },
    },
  },
};

test("required scalar defaults follow their schema even when the generated type is renamed", () => {
  const output = applyApiScalarDefaults(generated, definitions);
  assert.match(output, /int64_t revision = 7;/);
  assert.match(output, /bool enabled = true;/);
  assert.match(output, /double interval = 2\.5;/);
  assert.match(output, /std::optional<int64_t> optional;/);
  assert.match(output, /x\.revision = j\.at\("revision"\)\.get<int64_t>\(\);/);
});

test("undeclared defaults keep existing zero initialization", () => {
  assert.equal(applyApiScalarDefaults(generated, {
    ConfigurationSchema: { required: ["revision"], properties: { revision: { type: "integer" } } },
  }), generated);
});

test("incompatible generated shape or unsafe numeric default cannot silently drop a schema default", () => {
  assert.throws(() => applyApiScalarDefaults(generated.replace("revision = 0", "revision{}"), definitions),
    /Missing generated scalar member/);
  const unsafe = structuredClone(definitions);
  unsafe.ConfigurationSchema.properties.revision.default = Number.MAX_SAFE_INTEGER + 1;
  assert.throws(() => applyApiScalarDefaults(generated, unsafe), /Invalid scalar default/);
});
