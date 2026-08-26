import fs from "fs"
import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import viteCompression from "vite-plugin-compression"
import { constants } from "zlib"
import { defineConfig } from "vite"

const textAssetPattern =
  /\.(html?|css|js|mjs|cjs|jsx|ts|tsx|json|svg|txt|xml|wasm|map)$/i

/**
 * The version shown in the header comes from version.mk, the same file the
 * package is built from, so the two can never drift apart. Reading it here
 * rather than asking the daemon keeps the header free of a request whose only
 * purpose would be to print a number that is fixed at build time anyway.
 */
function packageVersion() {
  let raw = ""
  try {
    raw = fs.readFileSync(path.resolve(__dirname, "../version.mk"), "utf8")
  } catch {
    // Building the frontend on its own is allowed; the header just says nothing.
    return ""
  }

  const version = raw.match(/KEEN_PBR_VERSION\s*=\s*(.+)/)?.[1].trim()
  if (!version) return ""

  // The package build assigns the same 14-digit timestamp to the daemon, IPK
  // and frontend. Rejecting any other override prevents a legacy counter such
  // as `12` from silently returning as a plausible build identity.
  const stamp = process.env.KEEN_PBR_RELEASE_OVERRIDE?.trim()
  if (stamp && !/^\d{14}$/.test(stamp)) {
    throw new Error(
      "KEEN_PBR_RELEASE_OVERRIDE must be a 14-digit build timestamp"
    )
  }
  if (stamp) return `v${version}-${stamp}`

  // A standalone preview has no package identity to claim. Show only the
  // semantic version; the historical release counter (for example sb.12) is
  // not a build timestamp and must never reappear in the header.
  return `v${version}`
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  define: {
    __APP_VERSION__: JSON.stringify(packageVersion()),
  },
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
