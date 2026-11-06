import { defineConfig } from '@playwright/test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDir = dirname(fileURLToPath(import.meta.url));
const testDir = resolve(projectDir, 'specs');
const repositoryRoot = resolve(projectDir, '../..');
const port = process.env.SCADAVER_WEB_E2E_PORT || '18888';
const apiKey = 'scadaver-e2e-loopback-only';
const baseURL = `http://127.0.0.1:${port}`;
const testDatabase = resolve(projectDir, '.web-e2e-devices.db');

export default defineConfig({
  testDir,
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  globalSetup: './global-setup.mjs',
  webServer: {
    command: `cargo run --quiet -- web --host 127.0.0.1 --port ${port}`,
    cwd: repositoryRoot,
    url: `${baseURL}/health`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      SCADAVER_NO_BROWSER: '1',
      SCADAVER_TEST_API_KEY: apiKey,
      SCADAVER_TEST_LOOPBACK: '1',
      SCADAVER_DB_PATH: testDatabase,
    },
  },
  metadata: {
    apiKey,
  },
});
