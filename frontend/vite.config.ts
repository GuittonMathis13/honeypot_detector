import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls during development to the backend running on port 8000
      '/analyze': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});