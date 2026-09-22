// This host uses isolated fixtures. Never run it against production.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir } from 'node:fs/promises';
const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const origin = process.argv[2];
assert.equal(new URL(origin).hostname, '127.0.0.1');
const output = process.env.IDENTITY_MFA_SCREENSHOTS || '/tmp/identity-mfa-screenshots';
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.request.get(`${origin}/test-signin/administrator`);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => { errors.push(error.message); console.error(error.message); });
  page.on('console', message => { if (message.type() === 'error') console.error(message.text()); });
  page.setDefaultTimeout(15000);
  await page.goto(`${origin}/management/users/user-1/edit`);
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: 'Redefinir autenticação de dois fatores', exact: true }).click();
  const form = page.locator('[data-mfa-reset-confirmation]');
  await form.waitFor();
  const confirm = page.getByRole('button', { name: 'Confirmar redefinição', exact: true });
  assert.equal(await confirm.isDisabled(), true);
  await page.getByLabel('Motivo da redefinição', { exact: true }).fill('Chamado 123: perda do aparelho confirmada pelo suporte.');
  await page.getByLabel('Digite alice para confirmar a conta', { exact: true }).fill('bob');
  await page.getByLabel('Verifiquei a identidade do titular pelo procedimento de suporte.', { exact: true }).check();
  assert.equal(await confirm.isDisabled(), true);
  await page.getByLabel('Digite alice para confirmar a conta', { exact: true }).fill('alice');
  await page.waitForFunction(() => document.querySelector('[data-mfa-reset-confirmation] button[type=submit]')?.disabled === false);
  assert.equal(await confirm.isEnabled(), true);
  for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `${output}/${name}-confirmation.png`, fullPage: true, animations: 'disabled' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${name}: overflow`);
  }
  await form.getByRole('button', { name: 'Cancelar', exact: true }).click();
  await form.waitFor({ state: 'detached' });
  assert.equal(await form.count(), 0);
  await page.getByRole('button', { name: 'Redefinir autenticação de dois fatores', exact: true }).click();
  assert.equal(await page.locator('#mfa-reset-reason').inputValue(), '');
  await page.locator('#mfa-reset-reason').fill('Chamado 123: perda do aparelho confirmada pelo suporte.');
  await page.locator('#mfa-reset-confirmation').fill('alice');
  await page.locator('#mfa-reset-verified').check();
  await confirm.click();
  await page.getByRole('status').filter({ hasText: 'Autenticação de dois fatores redefinida.' }).waitFor();
  assert.equal(await form.count(), 0);
  await page.getByText('Aguardando novo autenticador', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Redefinir autenticação de dois fatores', exact: true }).count(), 0);
  await page.screenshot({ path: `${output}/mobile-success.png`, fullPage: true, animations: 'disabled' });
  await page.goto(`${origin}/management/users/user-1?culture=en-US&ui-culture=en-US`);
  await page.getByRole('button', { name: 'Reset two-factor authentication', exact: true }).waitFor();
  assert.deepEqual(errors, []);
  console.log('PASS: edit/detail, cancellation, required reason/identity/target, reset success, reenrollment state, translations, desktop/mobile without overflow or JS errors.');
} finally { await browser.close(); }
