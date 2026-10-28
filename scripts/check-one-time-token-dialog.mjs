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
  const value = dialog.locator('.one-time-token-dialog__value textarea');

  await page.screenshot({ path: `${output}/provisioning.png`, fullPage: true, animations: 'disabled' });

  // Issuing opens the dialog with the token; nothing is rendered inline.
  const generate = page.locator('.temporary-token-panel .sui-btn').filter({ hasText: /Gerar|Generate/ });
  await generate.click();
  await dialog.waitFor();
  assert.equal(await value.inputValue(), 'stub-one-time-token-value');
  // The button stops spinning once the token is issued: reading it is not a wait.
  await page.waitForTimeout(500);
  assert.equal(await generate.getAttribute('aria-busy'), null, 'generate button busy while the dialog is open');
  assert.match(await value.evaluate(element => getComputedStyle(element).fontFamily), /mono/i, 'token value is not monospace');
  assert.equal(await page.locator('.temporary-token-panel .sui-alert--success').count(), 0, 'hidden notice while the dialog is open');
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
  await page.locator('.temporary-token-panel .sui-alert--success').waitFor();

  // Discarding on purpose closes without copying.
  await page.locator('.temporary-token-panel .sui-btn').filter({ hasText: /Gerar|Generate/ }).click();
  await dialog.waitFor();
  await dialog.getByRole('button', { name: /^(Concluído|Done)$/ }).click();
  await discard.waitFor();
  await dialog.getByRole('button', { name: /^(Fechar sem copiar|Close without copying)$/ }).click();
  await page.getByRole('dialog').waitFor({ state: 'detached' });

  // Preview: the confirmation is a checkbox and gates the apply button.
  await page.locator('.manifest-panel .sui-btn').filter({ hasText: /preview/i }).click();
  const confirmation = page.locator('#provisioning-confirmation');
  await confirmation.waitFor();
  assert.equal(await confirmation.getAttribute('type'), 'checkbox');
  await page.screenshot({ path: `${output}/provisioning-plan.png`, fullPage: true, animations: 'disabled' });

  // Pages sharing the one-time-token panel and the client wizard.
  const shots = [
    ['registrations', '/management/clients/registrations', '.registration-tokens'],
    ['draft-identity', '/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/identity', '#client-id'],
    ['draft-protocol', '/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/protocol', '#grant-authorization-code'],
    ['draft-permissions', '/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/permissions', 'input[name="selectedScopes"]'],
    ['draft-uris', '/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/uris', '#redirect-uri-0'],
  ];
  for (const [name, path, ready] of shots) {
    for (const [suffix, viewport] of [['', { width: 1440, height: 1000 }], ['-mobile', { width: 390, height: 844 }]]) {
      await page.setViewportSize(viewport);
      await page.goto(`${origin}${path}`);
      await page.waitForLoadState('networkidle');
      await page.locator(ready).first().waitFor();
      await page.screenshot({ path: `${output}/${name}${suffix}.png`, fullPage: true, animations: 'disabled' });
    }
  }
  await page.goto(`${origin}/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/protocol`);
  await page.locator('#grant-authorization-code').waitFor();
  assert.equal(await page.locator('#grant-authorization-code').getAttribute('type'), 'checkbox');
  await page.goto(`${origin}/management/clients/drafts/96774ce4-a56d-4c50-8668-d25f046b30fc/permissions`);
  const scope = page.locator('input[name="selectedScopes"]').first();
  await scope.waitFor();
  assert.equal(await scope.getAttribute('type'), 'checkbox');
  await page.goto(`${origin}/management/clients/registrations`);
  await page.locator('.registration-tokens').waitFor();
  assert.equal(await page.locator('.registrations-footer nav.sui-pagination').count(), 1, 'registrations pagination');

  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}
