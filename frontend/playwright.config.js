import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

// End-to-end tests run the real stack: the FastAPI app with the unmodified
// analysis pipeline, and the Vite dev server in front of it. They contact
// PyPI, GitHub and OSV, so they need a network connection and SWI-Prolog.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const apiPort = Number(process.env.E2E_API_PORT) || 8765;
const webPort = Number(process.env.E2E_WEB_PORT) || 5273;
const python = process.env.E2E_PYTHON || path.join(root, ".venv", "bin", "python");

export default defineConfig({
  testDir: "./e2e",
  timeout: 240_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  outputDir: "./test-results",
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `"${python}" -m uvicorn ephemeral_scope.api.app:create_app --factory --port ${apiPort}`,
      cwd: root,
      url: `http://127.0.0.1:${apiPort}/api/health`,
      reuseExistingServer: true,
      timeout: 120_000,
    },
    {
      command: `npm run dev -- --host 127.0.0.1 --port ${webPort}`,
      url: `http://127.0.0.1:${webPort}`,
      env: { VITE_API_TARGET: `http://127.0.0.1:${apiPort}` },
      reuseExistingServer: true,
      timeout: 60_000,
    },
  ],
});
