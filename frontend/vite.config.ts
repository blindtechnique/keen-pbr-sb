import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import viteCompression from "vite-plugin-compression"
import { constants } from "zlib"
import { defineConfig } from "vite"

const textAssetPattern =
  /\.(html?|css|js|mjs|cjs|jsx|ts|tsx|json|svg|txt|xml|wasm|map)$/i

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    viteCompression({
      algorithm: "gzip",
      ext: ".gz",
      threshold: 0,
      filter: textAssetPattern,
      deleteOriginFile: false,
      disable: mode === "development",
      compressionOptions: {
        level: constants.Z_BEST_COMPRESSION,
      },
    }),
  ],
  build: {
    outDir: process.env.KEEN_PBR_FRONTEND_OUT_DIR || "dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // The libraries change only when we upgrade them, while our own code
        // changes every release. Keeping them apart means an update re-fetches
        // the small half instead of the whole megabyte.
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return undefined
          }
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
            return "vendor-react"
          }
          if (id.includes("@tanstack")) {
            return "vendor-query"
          }
          if (id.includes("i18next")) {
            return "vendor-i18n"
          }
          return "vendor"
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: process.env.ROUTER_URL || "http://192.168.54.1:12121",
        changeOrigin: true,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}))
