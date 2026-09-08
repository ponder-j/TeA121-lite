import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const useMock = process.env.VITE_USE_MOCK || env.VITE_USE_MOCK || (mode === 'test' ? 'true' : 'false');
  return {
    plugins: [react()],
    define: {
      'import.meta.env.VITE_USE_MOCK': JSON.stringify(useMock),
      'import.meta.env.VITE_API_BASE': JSON.stringify(env.VITE_API_BASE || '/api/v1'),
    },
    server: {
      host: '0.0.0.0',
      port: 4173,
      proxy: {
        '/api': {
          target: env.VITE_API_PROXY_TARGET || 'http://localhost:8000',
          changeOrigin: true,
        },
      },
    },
  };
});
