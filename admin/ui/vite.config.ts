import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  server: {
    allowedHosts: true,
    proxy: {
      // changeOrigin stays false: the admin compares Origin with Host for
      // cookie-authenticated writes, so rewriting Host would 403 every POST.
      '/api': { target: process.env.RP_DEV_TARGET ?? 'https://localhost:8443', changeOrigin: false, secure: false },
    },
  },
})
