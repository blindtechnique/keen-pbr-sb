#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/src/api/generated"

MODE="write"
if [ "${1:-}" = "--check" ]; then
  MODE="check"
  shift
fi

# Code generation must be reproducible: an unpinned QuickType update can
# otherwise change a committed header while docs/openapi.yaml stays untouched.
JS_YAML_PACKAGE="js-yaml@5.2.3"
QUICKTYPE_PACKAGE="quicktype@26.0.0"
if [ "$#" -ne 0 ]; then
  echo "Usage: $0 [--check]" >&2
  exit 2
fi

# Step 1: Extract components/schemas from the OpenAPI 3.1 YAML and create a
# JSON Schema $defs document with a synthetic root that references ALL schemas.
# This ensures QuickType generates types for config, health, cache, and routing.
# Uses only Node.js tooling: npx js-yaml + node built-ins.
# Keep XXXXXX at the end: BusyBox mktemp (used by lightweight CI/build
# containers) does not support a suffix after the replacement template.
# Stable filenames inside the temporary directory also keep QuickType's
# synthetic root name deterministic (`ApiTypes`).
TMP_DIR="$(mktemp -d /tmp/keen-pbr-api-types-XXXXXX)"
SCHEMA_TMP="$TMP_DIR/api-types.json"
TYPES_TMP="$TMP_DIR/api-types.hpp"
trap 'rm -rf "$TMP_DIR"' EXIT

npx --yes "$JS_YAML_PACKAGE" "$REPO_ROOT/docs/openapi.yaml" \
  | node -e "
let d = '';
process.stdin.on('data', c => d += c);
process.stdin.on('end', () => {
  const spec = JSON.parse(d);
  const schemas = spec.components.schemas;

  // Remove OpenAPI-specific extensions that QuickType does not understand
  function clean(obj) {
    if (typeof obj !== 'object' || obj === null) return;
    if (Array.isArray(obj)) { obj.forEach(clean); return; }
    delete obj.discriminator;
    delete obj.example;
    delete obj.description;
    Object.values(obj).forEach(clean);
  }
  clean(schemas);

  // Rewrite \$ref paths from OpenAPI to JSON Schema \$defs format
  function rewriteRefs(obj) {
    if (typeof obj !== 'object' || obj === null) return;
    if (Array.isArray(obj)) { obj.forEach(rewriteRefs); return; }
    if (obj['\$ref']) {
      obj['\$ref'] = obj['\$ref'].replace('#/components/schemas/', '#/\$defs/');
    }
    Object.values(obj).forEach(rewriteRefs);
  }
  rewriteRefs(schemas);

  // Synthetic root: reference ALL schemas so QuickType generates every type.
  // Each schema becomes a property of the root, driving code generation.
  const rootProperties = {};
  for (const name of Object.keys(schemas)) {
    rootProperties[name] = { '\$ref': '#/\$defs/' + name };
  }

  const jsonSchema = {
    '\$schema': 'http://json-schema.org/draft-07/schema#',
    '\$defs': schemas,
    'type': 'object',
    'properties': rootProperties
  };

  process.stdout.write(JSON.stringify(jsonSchema, null, 2));
});
" > "$SCHEMA_TMP"

# Step 2: Run QuickType to generate C++ types
npx --yes "$QUICKTYPE_PACKAGE" \
  --lang cpp \
  --src "$SCHEMA_TMP" \
  --src-lang schema \
  --namespace keen_pbr3::api \
  --no-boost \
  --code-format with-struct \
  -o "$TYPES_TMP"

# Step 3: Post-process: fix include path and prepend required system headers
node -e "
const fs = require('fs');
let content = fs.readFileSync('$TYPES_TMP', 'utf8');

// Fix nlohmann include path
content = content.replace('#include \"json.hpp\"', '#include <nlohmann/json.hpp>');

// Add cstdint and map includes (QuickType omits them)
content = content.replace(
  '#include <optional>',
  '#include <cstdint>\n#include <map>\n#include <optional>'
);

// Значения по умолчанию для скалярных полей.
//
// quicktype объявляет их как \`bool flag;\` и \`int64_t value;\`. Это
// default-initialization: при \`T x;\` значение неопределённо, и первое же
// чтение — неопределённое поведение. UBSan поймал ровно это: «load of value 49,
// which is not a valid value for type 'bool'» при копировании
// InternalVpnServerElement. Инициализатор в объявлении делает весь класс ошибки
// невозможным независимо от того, как объект создан.
//
// Перечисления намеренно не трогаем: \`= {}\` дало бы им первый по порядку
// элемент, а это выбор значения по смыслу, а не защита от мусора.
content = content.replace(
  /^(\s+)bool ([a-z_][a-z0-9_]*);\$/gm,
  '\$1bool \$2 = false;'
);
content = content.replace(
  /^(\s+)(int64_t|double) ([a-z_][a-z0-9_]*);\$/gm,
  '\$1\$2 \$3 = 0;'
);

// Add generation comment at the top
const header = '// Generated from docs/openapi.yaml via build_scripts/generate_api_types.sh\n' +
               '// Run \"make generate\" to regenerate (requires Node.js).\n\n';
content = header + content;

fs.writeFileSync('$TYPES_TMP', content);
"

GENERATED_TYPES="$REPO_ROOT/src/api/generated/api_types.hpp"
if [ "$MODE" = "check" ]; then
  if ! cmp -s "$TYPES_TMP" "$GENERATED_TYPES"; then
    echo "Generated backend API types are out of date." >&2
    echo "Run 'make generate' and commit src/api/generated/api_types.hpp." >&2
    diff -u "$GENERATED_TYPES" "$TYPES_TMP" || true
    exit 1
  fi
  echo "Backend API types are up to date."
else
  cp "$TYPES_TMP" "$GENERATED_TYPES"
fi
