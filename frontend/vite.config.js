import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API runs as its own process in development. Everything under /api is
// proxied to it, so the browser only ever talks to one origin.
const apiTarget = process.env.VITE_API_TARGET || "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PORT) || 5273,
    strictPort: true,
    proxy: { "/api": { target: apiTarget, changeOrigin: true } },
  },
  preview: {
    port: Number(process.env.PORT) || 5273,
    strictPort: true,
    proxy: { "/api": { target: apiTarget, changeOrigin: true } },
  },
});
