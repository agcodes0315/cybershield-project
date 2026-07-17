import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  server: {
    host: '127.0.0.1',
    port: 5173,

    proxy: {
      /*
       * Existing Node/Express API gateway.
       *
       * Authentication, URL scanning, admin, reports and the older
       * CyberShield modules continue using this proxy.
       */
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
      },

      /*
       * New FastAPI cyber-resilience detection engine.
       *
       * Frontend requests beginning with /engine are forwarded to
       * port 8000 after the /engine prefix is removed.
       *
       * Example:
       * /engine/api/resilience/health
       * becomes
       * http://127.0.0.1:8000/api/resilience/health
       */
      '/engine': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/engine/, ''),
      },

      '/ws': {
        target: 'ws://127.0.0.1:5000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
});