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
  await page.goto(`${origin}/management/users/user-1`);
  await page.waitForLoadState('networkidle');
  assert.equal(await page.locator('#mfa-reset-reason').count(), 0);
  assert.equal(await page.locator('#new-password').count(), 0);
  assert.equal(await page.locator('#delete-user-confirmation').count(), 0);
  const accountActions = page.getByRole('button', { name: 'Ações da conta', exact: true });
  const actionsMenu = page.locator('#user-account-actions-menu');
  assert.equal(await accountActions.isVisible(), false);
  assert.equal(await actionsMenu.isVisible(), true);
  const desktopActionPositions = await page.locator('.user-account-action').evaluateAll(elements =>
    elements.map(element => Math.round(element.getBoundingClientRect().top)));
  assert.equal(new Set(desktopActionPositions).size, 1);
  await page.screenshot({ path: `${output}/desktop-actions.png`, fullPage: true, animations: 'disabled' });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'desktop: action row overflow');
  await page.setViewportSize({ width: 390, height: 844 });
  await accountActions.waitFor();
  assert.equal(await actionsMenu.isVisible(), false);
  assert.equal(await accountActions.getAttribute('aria-expanded'), 'false');
  await accountActions.click();
  await actionsMenu.waitFor();
  assert.equal(await accountActions.getAttribute('aria-expanded'), 'true');
  assert.match(await page.getByRole('link', { name: /Redefinir autenticação de dois fatores/ }).getAttribute('href'), /users\/user-1\/actions\/mfa$/);
  assert.match(await page.getByRole('link', { name: /Gerenciar acesso/ }).getAttribute('href'), /users\/user-1\/actions\/access$/);
  assert.match(await page.getByRole('link', { name: /Redefinir senha/ }).getAttribute('href'), /users\/user-1\/actions\/password$/);
  assert.match(await page.getByRole('link', { name: /Excluir conta do provedor/ }).getAttribute('href'), /users\/user-1\/actions\/delete$/);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: `${output}/mobile-action-menu.png`, fullPage: true, animations: 'disabled' });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'mobile: action menu overflow');
  await accountActions.click();
  await actionsMenu.waitFor({ state: 'hidden' });
  assert.equal(await accountActions.getAttribute('aria-expanded'), 'false');
  for (const [route, marker] of [
    ['access', '#confirm-account-lockout'],
    ['password', '#new-password'],
    ['delete', '#delete-user-confirmation'],
  ]) {
    await page.goto(`${origin}/management/users/user-1/actions/${route}`);
    await page.waitForLoadState('networkidle');
    await page.locator(marker).waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: `${output}/mobile-${route}.png`, fullPage: true, animations: 'disabled' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${route}: mobile overflow`);
  }
  await page.goto(`${origin}/management/users/user-1`);
  await page.waitForLoadState('networkidle');
  await accountActions.click();
  await actionsMenu.waitFor();
  await page.getByRole('link', { name: /Redefinir autenticação de dois fatores/ }).click();
  await page.waitForURL('**/management/users/user-1/actions/mfa');
  await page.getByRole('button', { name: 'Redefinir autenticação de dois fatores', exact: true }).click();
  const form = page.locator('[data-mfa-reset-confirmation]');
  await form.waitFor();
  assert.equal(await page.locator('#mfa-reset-reason').evaluate(element => element.tagName), 'INPUT');
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
  assert.deepEqual(errors, []);
  console.log('PASS: collapsed action menu, dedicated MFA route, single-line reason, cancellation, required reason/identity/target, reset success, desktop/mobile without overflow or JS errors.');
} finally { await browser.close(); }
