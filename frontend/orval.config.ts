import { defineConfig } from "orval"

export default defineConfig({
  keenApi: {
    input: {
      target: "../docs/openapi.yaml",
      // The native import operation carries long-lived private keys and must
      // never acquire the generated apiFetch/TanStack retry surface. The
      // operation remains in OpenAPI and its response models are still
      // generated; only the uniquely tagged secret-bearing client method is
      // excluded. The bodyless preflight remains generated/replay-safe.
      filters: {
        mode: "exclude",
        tags: ["Native secret transport"],
      },
    },
    output: {
      target: "./src/api/generated/keen-api.ts",
      schemas: "./src/api/generated/model",
      client: "react-query",
      mode: "split",
      override: {
        mutator: {
          path: "./src/api/client.ts",
          name: "apiFetch",
        },
      },
    },
  },
})
