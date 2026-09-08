# Routing list source formats

Choose the format explicitly in the list editor. There is no filename/content
guessing for JSON/YAML. These formats carry domains and IP/CIDR entries, not
complete Clash or sing-box configurations or rule commands.

## Supported structures

- `text` (default): one domain, IP address or network per line. Existing text
  source behavior and automatic handling of remote `.srs` files are unchanged.
- `json-array`: a root array containing strings only:

  ```json
  ["example.org", "*.example.net", "192.0.2.19/24", "2001:db8::1"]
  ```

- `yaml-payload`: exactly one `payload` block sequence:

  ```yaml
  payload:
    - example.org
    - '*.example.net'
    - 192.0.2.19/24
    - "2001:db8::1"
  ```

  Single-line plain, single-quoted and double-quoted scalars and comments are
  supported. Flow collections, anchors/aliases, tags, nested objects, directives,
  multiple documents, additional root fields and classical rule commands are not.
  An empty payload is rejected; use an empty JSON array for an explicit empty list.

## Where the format applies

- File upload or pasted contents: **Add to draft** parses the entire source and
  adds all unique normalized values to the current local editor. It does not
  save, apply, restart services or choose the list name. Save remains a separate
  normal action. The selected upload format does not change an existing URL's format.
- Remote URL or a path on the router: `lists.<name>.source_format` persists the
  selected syntax. Scheduled/manual refresh uses the same parser before
  publishing the new cache. Missing format means `text`.
- Optional preview uses the same structured parser but displays only the first
  50 unique entries and 50 errors. Actual import is not capped at 50 entries.

One source format applies to both URL and router-file sources in the same list;
inline editor entries are already normalized text. Use separate lists if URL and
router file have different formats.

## Normalization, errors and limits

The shared runtime `ListParser` canonicalizes IP addresses, masks host bits in
CIDRs and removes duplicates. Domains are case-insensitive; `*.example.org`
and `example.org` both use native root-and-subdomain matching. Exact-only domain
or rule-order semantics from other formats are not inferred.

Structured input/output is limited to 2 MiB and 50000 entries; scalars are limited
to 4096 bytes. YAML/text physical lines have the same 4096-byte bound; minified
JSON may have a longer physical line. Errors include source line numbers and
stable localized codes. If any entry is invalid, no partial contents are added
or published. The existing cache is preserved; format/revision changes cannot
reuse a differently interpreted cache or its HTTP validators. Previously
configured shrink handling still applies to a successfully decoded remote list.

`POST /api/lists/import` is an authenticated, non-mutating normalization endpoint
with `{ "format": "json-array", "text": "[\"example.org\"]" }`. It returns
`complete`, all `domains`/`ip_cidrs`, duplicate count and bounded errors. Both
entry arrays are empty when `complete` is false. It never creates a server draft.

## Кратко по-русски

В редакторе явно выберите обычный текст, JSON-массив строк или YAML со списком
`payload`. Кнопка «Добавить в черновик» добавляет весь корректный список, а не
только показанные в превью 50 записей. При ошибке указаны причина и строка;
форма и сохранённая конфигурация не заменяются частичным результатом.
Для URL/файла на роутере формат сохраняется и применяется при обновлении.
Полные конфигурации Clash/sing-box и команды правил не поддерживаются.
