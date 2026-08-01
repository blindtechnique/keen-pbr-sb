# Agent Notes

This checkout is the canonical Release 12 worktree. Do not copy new changes
into sibling archival source directories or switch/reset its dirty branch.

## Build

Use the root `Makefile`. Its native GCC build directory is
`cmake-build-gcc`; do not assume a generic `cmake-build` directory:

```sh
make
```

For a production build run `make`. For backend tests run `make test
BUILD_JOBS=4`; this also runs the crash-diagnostics smoke test.

The code must remain C++17-compatible with the Keenetic GCC 8 toolchain.
Package and init scripts must remain compatible with BusyBox `sh`; avoid Bash
features in target-side scripts.

## Generated Files

Never edit generated files by hand. Update the source schema/config and run the
appropriate codegen command instead.

- Backend API types (`src/api/generated/api_types.hpp`): run `make generate`.
- Verify backend API types without rewriting tracked files: run
  `make generate-check`.
- Frontend API client/models (`frontend/src/api/generated/`): run `make frontend-api-generate`.

## Frontend

Frontend lives in the `frontend/` folder.
Always use Bun/Bunx as the package manager. CI uses Bun 1.3.14.
We are using base-ui instead of radix-ui.

Do not compile C++ when only frontend code or prose was edited.

Minimum frontend checks are `bun run lint`, `bun run i18n:check`, `bun test`,
`bun run typecheck`, and `bun run build`. If `docs/openapi.yaml` changes, run
both backend and frontend code generation and verify both generated trees.

## Translations

Run `bun run i18n:check` from `frontend/` after changing UI text or translation
calls. Dynamic `t()` arguments must be declared with their finite key family in
`frontend/scripts/i18n-dynamic-keys.ts`; do not silence them with broad source
exclusions.

## Acceptance boundary

Frontend-only preview is not backend validation. Changes to routing, firewall,
DNS, lifecycle, package scripts, generated API contracts, or transport-manager
require an IPK build and the router acceptance checklist in
`ALPHA-ROUTER-TEST.ru.md` before release promotion.

Never add local credentials, exported transport configurations, or device
secrets. In particular, do not stage untracked `transports.json` files.
