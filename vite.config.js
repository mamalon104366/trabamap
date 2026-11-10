import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Rutas relativas: la app empaquetada carga dist/index.html con file://, donde "/assets" no existe.
  base: './',
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/nmap-master/**', '**/node_modules/**', '**/dist/**', '**/artifacts/**', '**/release/**', '**/build/**'] },
  },
});
