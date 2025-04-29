import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/process_data": {
        target: "https://nautilus-twitter.mystenlabs.com",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
