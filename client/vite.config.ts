/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:3000',
      '/events': {
        target: 'http://localhost:3000',
        // SSE needs no timeout
        timeout: 0,
      },
      '/entries': 'http://localhost:3000',
      '/weight': 'http://localhost:3000',
      '/links': 'http://localhost:3000',
      '/settings/export': 'http://localhost:3000',
      '/settings/import': 'http://localhost:3000',
      '/settings/macros': 'http://localhost:3000',
      '/settings/preferences': 'http://localhost:3000',
      '/settings/ai': 'http://localhost:3000',
      '/settings/password': 'http://localhost:3000',
      '/settings/link': 'http://localhost:3000',
      '/settings/email': 'http://localhost:3000',
      '/2fa': 'http://localhost:3000',
      '/admin': 'http://localhost:3000',
      '/delete': 'http://localhost:3000',
      '/imprint/address.svg': 'http://localhost:3000',
      '/imprint/email.svg': 'http://localhost:3000',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  test: {
    // Two projects rather than one jsdom environment for everything, so the
    // original intent here survives: pure logic needs no DOM, and paying for
    // one on every `*.test.ts` would make the fast suite slow to no purpose.
    // The split is by file extension, which needs no per-file opt-in — a
    // component test is a .tsx, a logic test is a .ts.
    projects: [
      {
        extends: true,
        test: {
          name: 'logic',
          // Pure logic modules under src/lib need no DOM; keep the runner lean.
          environment: 'node',
          // tests/ holds build/dependency-boundary tests that read the lockfile
          // and node_modules via node builtins. They live outside src so
          // `tsc -b` (which includes only src and has no @types/node) stays
          // clean.
          include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'components',
          environment: 'jsdom',
          include: ['src/**/*.test.tsx'],
          setupFiles: ['./src/test/setup.ts'],
          // Testing Library's auto-cleanup relies on the global afterEach.
          globals: true,
        },
      },
    ],
  },
});
