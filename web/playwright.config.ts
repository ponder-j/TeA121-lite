import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  timeout: 45_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: process.env.TEA121_WEB_URL ?? 'http://localhost:4173',
    trace: 'retain-on-failure',
  },
});
