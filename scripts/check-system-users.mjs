// This host uses isolated fixtures. Never run it against production.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir } from 'node:fs/promises';
const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const origin = process.argv[2];
assert.equal(new URL(origin).hostname, '127.0.0.1');
const output = process.env.IDENTITY_SYSTEM_USERS_SCREENSHOTS || '/tmp/identity-system-users-screenshots';
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  await context.request.get(`${origin}/test-signin/administrator`);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => { errors.push(error.message); console.error(error.message); });
  page.setDefaultTimeout(15000);
  await page.goto(`${origin}/management/system-users`);
  await page.waitForLoadState('networkidle');

  // Empty state, then create.
  await page.getByRole('button', { name: /Novo usuário de sistema|New system user/ }).click();
  await page.locator('#system-user-name').fill('agent-github-engineer');
  await page.locator('#system-user-display-name').fill('GitHub engineer');
  await page.getByRole('button', { name: /Criar usuário de sistema|Create system user/ }).click();
  await page.locator('.system-users-table').getByText('GitHub engineer').waitFor();
  await page.locator('.sui-toast, [role="status"]').filter({ hasText: /criado|created/ }).first().waitFor();

  // Credentials panel opened on creation; an unknown client is refused in a toast.
  const panel = page.locator('.system-user-credentials');
  await panel.waitFor();
  await page.locator('#system-user-enrollment-client').fill('unknown-client');
  await page.locator('#system-user-enrollment-label').fill('pod github-engineer');
  await page.getByRole('button', { name: /Emitir código|Issue code/ }).click();
  await page.locator('.sui-toast, [role="alert"]').filter({ hasText: /cliente|client/i }).first().waitFor();

  // Issue for the right client: the code appears once, in the shared dialog.
  await page.locator('#system-user-enrollment-client').fill('headless-agent');
  await page.locator('#system-user-enrollment-label').fill('pod github-engineer');
  await page.getByRole('button', { name: /Emitir código|Issue code/ }).click();
  const dialog = page.getByRole('dialog');
  await dialog.waitFor();
  assert.equal(await dialog.locator('textarea').inputValue(), 'sys_enroll_stub-enrollment-code');
  assert.match(await dialog.innerText(), /system-user-enrollment/);
  await page.screenshot({ path: `${output}/code-dialog.png`, animations: 'disabled' });
  await dialog.getByRole('button', { name: /Copiar código|Copy code/ }).click();
  await dialog.getByRole('button', { name: /Copiado|Copied/ }).waitFor();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'sys_enroll_stub-enrollment-code');
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'detached' });

  // Listed as awaiting redemption; revoke with confirmation.
  await panel.getByText(/Aguardando troca|Awaiting redemption/).waitFor();
  await page.screenshot({ path: `${output}/credentials.png`, fullPage: true, animations: 'disabled' });
  await panel.getByRole('button', { name: /Revogar|Revoke/ }).click();
  await page.getByRole('dialog').getByRole('button', { name: /Confirmar|Confirm|OK/ }).click();
  await panel.getByText(/Revogado|Revoked/).waitFor();

  // Disable with confirmation.
  await page.locator('.system-users-table').getByRole('button', { name: /Desativar|Disable/ }).click();
  await page.getByRole('dialog').getByRole('button', { name: /Confirmar|Confirm|OK/ }).click();
  await page.locator('.system-users-table').getByText(/Desativado|Disabled/).waitFor();

  // Mobile: nothing leaves the viewport.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(300);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'mobile overflow');
  await page.screenshot({ path: `${output}/mobile.png`, fullPage: true, animations: 'disabled' });

  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}
