import { expect, test as base, type Page } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EMAIL = process.env.E2E_EMAIL ?? 'admin@vulnreplay.local';
const PASSWORD = process.env.E2E_PASSWORD ?? '';
const SHOTS = process.env.E2E_SCREENSHOT_DIR;
const SAMPLES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../samples');

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: false });
}

// One signed-in page is shared by all tests: the API rate-limits logins (10/min per client).
let shared: Page;
const test = base.extend<{ page: Page }>({ page: async ({}, use) => { await use(shared); } });
test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
  base.skip(!PASSWORD, 'E2E_PASSWORD not set');
  shared = await browser.newPage();
  await shared.goto('/');
  await shared.getByLabel('Email').fill(EMAIL);
  await shared.getByLabel('Password').fill(PASSWORD);
  await shared.getByRole('button', { name: 'Sign in' }).click();
  await expect(shared.getByRole('heading', { name: 'Overview' })).toBeVisible();
});

test.beforeEach(async ({ page }) => {
  await page.getByRole('link', { name: /Overview/ }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});

test('overview shows live backend data', async ({ page }) => {
  await expect(page.getByText('Recent executions')).toBeVisible();
  await expect(page.getByTestId('classification').first()).toBeVisible();
  await shot(page, 'overview');
});

test('regression library lists tests with latest results and filters', async ({ page }) => {
  await page.getByRole('link', { name: /Regression Library/ }).click();
  await expect(page.getByRole('cell', { name: /IDOR: invoices readable/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /IDOR: invoices readable/ }).getByTestId('classification')).toBeVisible();
  await shot(page, 'regression-library');
  await page.getByLabel('Category').selectOption('sql_injection');
  await expect(page.getByRole('cell', { name: /SQL error leakage/ })).toBeVisible();
  await expect(page.getByRole('cell', { name: /IDOR/ })).toHaveCount(0);
});

test('attack scenario renders the multi-step flow', async ({ page }) => {
  await page.getByRole('link', { name: /Attack Scenarios/ }).click();
  await page.getByRole('button', { name: /IDOR: invoices readable/ }).click();
  await expect(page.getByTestId('attack-flow')).toBeVisible();
  await expect(page.getByText('attempt to access User A\'s resource').first()).toBeVisible();
  await shot(page, 'attack-scenario');
});

test('comparison report shows timeline and before/after diff', async ({ page }) => {
  await page.getByRole('link', { name: /Regression Library/ }).click();
  await page.getByRole('row', { name: /IDOR: invoices readable/ }).getByRole('link', { name: /History/ }).click();
  await expect(page.getByTestId('timeline')).toContainText('release-2.4');
  const after = page.getByLabel('after execution');
  const verified = await after.locator('option', { hasText: 'hotfix-2' }).getAttribute('value');
  await after.selectOption(verified!);
  await page.getByRole('button', { name: 'Compare' }).click();
  await expect(page.getByTestId('diff')).toContainText('status 200 -> 404');
  await expect(page.getByTestId('diff')).toContainText('previously exposed data is no longer present');
  await shot(page, 'comparison-report');
});

test('test generator shows code renderings and secrets', async ({ page }) => {
  await page.getByRole('link', { name: /Test Generator/ }).click();
  await page.getByRole('button', { name: /IDOR: invoices readable/ }).click();
  await expect(page.getByText('VULNREPLAY_SECRET_OWNER_PASSWORD')).toBeVisible();
  await page.getByRole('tab', { name: 'Pytest + HTTPX' }).click();
  await expect(page.locator('pre')).toContainText('def test_');
  await shot(page, 'test-generator');
});

test('execution page runs an approved test and shows step results', async ({ page }) => {
  await page.getByRole('link', { name: /Test Execution/ }).click();
  await page.getByLabel('Approved test').selectOption({ label: 'IDOR: invoices readable by other users' });
  await page.getByLabel('Authorized target').selectOption({ label: 'lab-patched (http://localhost:8002)' });
  await page.getByLabel('Label').fill('e2e-check');
  await page.getByRole('button', { name: 'Execute' }).click();
  await expect(page.getByTestId('execution-detail').getByTestId('classification')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('execution-detail')).toContainText('other user attempts access');
  await shot(page, 'test-execution');
});

test('evidence upload through the UI and viewer', async ({ page }) => {
  await page.getByRole('link', { name: /Evidence Library/ }).click();
  await page.getByLabel('Evidence file').setInputFiles(path.join(SAMPLES, 'idor-report.json'));
  await page.getByRole('button', { name: 'Import evidence' }).click();
  await expect(page.getByText(/Imported idor-report.json: 1 exchange/)).toBeVisible();
  await expect(page.getByTestId('exchange').first()).toBeVisible();
  await expect(page.getByTestId('exchange').first()).toContainText('[REDACTED]');
  await shot(page, 'evidence-library');
});

test('findings page and assistant answer', async ({ page }) => {
  await page.getByRole('link', { name: /Vulnerability Findings/ }).click();
  await page.getByRole('button', { name: /IDOR: invoices readable/ }).first().click();
  await page.getByRole('button', { name: 'Explain with assistant' }).click();
  await expect(page.getByTestId('assistant')).toContainText('Verified facts');
  await shot(page, 'findings');
});

test('settings and projects pages', async ({ page }) => {
  await page.getByRole('link', { name: /Projects/ }).click();
  await expect(page.getByText('lab-vulnerable')).toBeVisible();
  await shot(page, 'projects-targets');
  await page.getByRole('link', { name: /Settings/ }).click();
  await expect(page.getByText('Allowed target hosts')).toBeVisible();
  await page.getByRole('link', { name: /CI\/CD/ }).click();
  await expect(page.getByText('GitHub Actions workflow')).toBeVisible();
  await shot(page, 'cicd');
});
