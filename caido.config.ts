import { defineConfig } from "@caido-community/dev";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "tailwindcss";
// @ts-expect-error no declared types at this time
import tailwindPrimeui from "tailwindcss-primeui";
import tailwindCaido from "@caido/tailwindcss";
import path from "path";
import prefixwrap from "postcss-prefixwrap";

const id = "csp-auditor";

export default defineConfig({
  id,
  name: "CSP Auditor",
  description: "Content Security Policy vulnerability scanner and analyzer",
  version: "2.0.0",
  author: {
    name: "Amr Elsagaei",
    email: "amr@caido.io",
    url: "https://amrelsagaei.com",
  },
  plugins: [
    {
      kind: "backend",
      id: "csp-auditor-backend",
      root: "packages/backend",
    },
    {
      kind: "frontend",
      id: "csp-auditor-frontend",
      root: "packages/frontend",
      backend: {
        id: "csp-auditor-backend",
      },
      vite: {
        plugins: [vue()],
        build: {
          rollupOptions: {
            external: [
              "@caido/frontend-sdk",
              "@codemirror/autocomplete",
              "@codemirror/commands",
              "@codemirror/language",
              "@codemirror/lint",
              "@codemirror/search",
              "@codemirror/state",
              "@codemirror/view",
              "@lezer/common",
              "@lezer/highlight",
              "@lezer/lr",
              "vue",
            ],
          },
        },
        resolve: {
          alias: {
            "@": path.resolve(__dirname, "packages/frontend/src"),
          },
        },
        css: {
          postcss: {
            plugins: [
              prefixwrap(`#plugin--${id}`),
              tailwindcss({
                corePlugins: {
                  preflight: false,
                },
                content: [
                  "./packages/frontend/src/**/*.{vue,ts}",
                  "./node_modules/@caido/primevue/dist/primevue.mjs",
                ],
                darkMode: ["selector", '[data-mode="dark"]'],
                plugins: [tailwindPrimeui, tailwindCaido],
              }),
            ],
          },
        },
      },
    },
  ],
});
