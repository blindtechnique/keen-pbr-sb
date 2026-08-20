import { defineConfig } from "orval"

export default defineConfig({
  keenApi: {
    input: {
      target: "../docs/openapi.yaml",
      // Native import carries long-lived private keys, while delete and both
      // recovery operations are one-shot mutations whose ambiguous outcome
      // must stay locked. Keep their schemas in the shared contract while
      // excluding every operation from the generated apiFetch/TanStack retry
      // surface. The bodyless import preflight remains generated/replay-safe.
      filters: {
        mode: "exclude",
        tags: [
          "Native secret transport",
          "Native manual mutation transport",
        ],
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
