// Loads the real identity.js into a form shaped like the sign-in form (SUI
// field markup) in a browser whose UI language differs from the page's.
// Usage: node scripts/check-inline-validation.mjs <path-to-identity.js>
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const script = await readFile(process.argv[2], 'utf8');
const messages = JSON.stringify({ required: 'Preencha este campo.', email: 'Informe um e-mail válido.' })
  .replace(/"/g, '&quot;');
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ locale: 'en-US' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.setContent(`<html lang="pt-BR"><head>
    <meta name="sufficit-validation-messages" content="${messages}"></head><body>
    <form onsubmit="event.preventDefault(); window.submitted = (window.submitted || 0) + 1">
      <div class="sui-field"><label class="sui-field__label" for="username">E-mail</label>
        <div class="sui-text-field__control"><input class="sui-field__input" id="username" type="email" aria-describedby="" required /></div></div>
      <div class="sui-field"><label class="sui-field__label" for="password">Senha</label>
        <div class="sui-text-field__control"><input class="sui-field__input" id="password" type="password" required /></div></div>
      <button type="submit">Entrar</button>
    </form></body></html>`);
  await page.addScriptTag({ content: script });

  const usernameError = page.locator('#username-validation');
  const passwordError = page.locator('#password-validation');

  // Empty submit: messages under both fields, in the page language, focus on
  // the first, nothing submitted.
  await page.click('button');
  await usernameError.waitFor();
  assert.equal(await usernameError.textContent(), 'Preencha este campo.');
  assert.equal(await passwordError.textContent(), 'Preencha este campo.');
  assert.equal(await page.getAttribute('#username', 'aria-invalid'), 'true');
  assert.match(await page.getAttribute('#username', 'aria-describedby'), /username-validation/);
  await page.waitForFunction(() => document.activeElement?.id === 'username');
  assert.equal(await page.evaluate(() => window.submitted ?? 0), 0);

  // The message follows the field state while typing and goes away once valid.
  await page.fill('#username', 'abc');
  assert.equal(await usernameError.textContent(), 'Informe um e-mail válido.');
  await page.fill('#username', 'a@b.co');
  assert.equal(await usernameError.count(), 0);
  assert.equal(await page.getAttribute('#username', 'aria-invalid'), null);

  await page.fill('#password', 'x');
  assert.equal(await passwordError.count(), 0);
  await page.click('button');
  assert.equal(await page.evaluate(() => window.submitted), 1);
  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}
