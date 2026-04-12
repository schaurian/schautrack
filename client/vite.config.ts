import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
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
});
