import { defineConfig } from '@playwright/test';

// E2E tests run against a running stack (docker compose or native). Configure with:
//   E2E_BASE_URL (default http://localhost:8080), E2E_EMAIL, E2E_PASSWORD
//   PW_CHROME_PATH to use a locally installed Chrome instead of the Playwright build.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    launchOptions: process.env.PW_CHROME_PATH ? { executablePath: process.env.PW_CHROME_PATH, args: ['--no-sandbox'] } : {},
  },
});
