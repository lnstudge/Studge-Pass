import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");

export default defineConfig({
  // docs/ is served as the static root so /screenshots/... and /preview/status.json
  // are reachable, and nothing is fetched from outside this machine.
  publicDir: path.resolve(repoRoot, "docs"),
  server: {
    host: "127.0.0.1",
    port: 4400,
    strictPort: true,
    fs: { allow: [repoRoot] },
    watch: {
      // Edits made from Windows do not raise Linux file events on /mnt/c.
      usePolling: process.env.STUDGE_WSL === "1",
      interval: 400,
    },
  },
  build: {
    outDir: path.resolve(here, "dist"),
    emptyOutDir: true,
  },
});
