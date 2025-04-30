import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd());
  const API_TARGET = env.VITE_API_TARGET || 'https://nautilus-twitter.mystenlabs.com';
  console.log('API_TARGET:', API_TARGET);
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/process_data": {
          target: API_TARGET,
          changeOrigin: true,
          secure: false,
        },
        "/health_check": {
          target: API_TARGET,
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path,
        },
      },
    },
  };
});
