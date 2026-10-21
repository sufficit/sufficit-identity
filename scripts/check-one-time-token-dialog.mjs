// This host uses isolated fixtures. Never run it against production.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir } from 'node:fs/promises';
const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const origin = process.argv[2];
assert.equal(new URL(origin).hostname, '127.0.0.1');
const output = process.env.IDENTITY_TOKEN_DIALOG_SCREENSHOTS || '/tmp/identity-token-dialog-screenshots';
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
  await page.goto(`${origin}/management/provisioning`);
  await page.waitForLoadState('networkidle');

  const dialog = page.getByRole('dialog');
  const value = dialog.locator('textarea.one-time-token-dialog__value');

  // Issuing opens the dialog with the token; nothing is rendered inline.
  await page.locator('.temporary-token-panel .sui-btn').filter({ hasText: /Gerar|Generate/ }).click();
  await dialog.waitFor();
  assert.equal(await value.inputValue(), 'stub-one-time-token-value');
  assert.equal(await page.locator('.temporary-token-panel .inline-notice--success').count(), 0, 'hidden notice while the dialog is open');
  const box = await dialog.boundingBox();
  const copy = await dialog.getByRole('button', { name: /Copiar token|Copy token/ }).boundingBox();
  assert.ok(copy.x + copy.width <= box.x + box.width, 'copy button clipped by the dialog');
  await page.screenshot({ path: `${output}/dialog.png`, animations: 'disabled' });

  // Escape, the backdrop and the header close never drop a token not yet
  // copied: the dialog stays and asks inside itself.
  const discard = dialog.locator('.one-time-token-dialog__discard');
  await page.keyboard.press('Escape');
  await discard.waitFor();
  assert.equal(await value.inputValue(), 'stub-one-time-token-value');
  await page.screenshot({ path: `${output}/discard-confirm.png`, animations: 'disabled' });
  await page.mouse.click(10, 10);
  await page.locator('.sui-dialog__close').click();
  assert.equal(await page.getByRole('dialog').count(), 1);

  // Copy, then closing needs no confirmation.
  await dialog.getByRole('button', { name: /Copiar token|Copy token/ }).click();
  await discard.waitFor({ state: 'detached' });
  await dialog.getByRole('button', { name: /Copiado|Copied/ }).waitFor();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'stub-one-time-token-value');
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'detached' });
  await page.locator('.temporary-token-panel .inline-notice--success').waitFor();

  // Discarding on purpose closes without copying.
  await page.locator('.temporary-token-panel .sui-btn').filter({ hasText: /Gerar|Generate/ }).click();
  await dialog.waitFor();
  await dialog.getByRole('button', { name: /^(Concluído|Done)$/ }).click();
  await discard.waitFor();
  await dialog.getByRole('button', { name: /^(Fechar sem copiar|Close without copying)$/ }).click();
  await page.getByRole('dialog').waitFor({ state: 'detached' });

  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}
