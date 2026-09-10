// Invoked by Audience_browser_host_serves_authenticated_screen. The host uses
// test cookies and in-memory fixtures; never point this script at production.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const origin = process.argv[2];
assert.equal(new URL(origin).hostname, '127.0.0.1', 'Only isolated loopback hosts are allowed');
const output = fileURLToPath(new URL('../.impeccable/review/', import.meta.url));
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    await context.request.get(`${origin}/test-signin/administrator`);
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    async function selectScope() {
        const field = page.getByRole('combobox', { name: 'Scope de acesso à API', exact: true });
        if (await field.evaluate(element => element.tagName) === 'SELECT') await field.selectOption('scope-1');
        else { await field.click(); await page.getByRole('option', { name: 'test.scope', exact: true }).click(); }
    }
    async function assertInventoryFocus() {
        await page.waitForFunction(() => document.activeElement?.id === 'audiences-list-heading');
    }
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    await page.goto(`${origin}/management/audiences`);
    await page.getByRole('button', { name: 'Vincular audiência', exact: true }).click();
    await page.getByLabel('Identificador da audiência', { exact: true }).fill('browser-api');
    await selectScope();
    await page.getByRole('button', { name: 'Salvar vínculo', exact: true }).click();
    await page.getByRole('status').filter({ hasText: 'Audiência vinculada.' }).waitFor();
    await assertInventoryFocus();
    await page.getByRole('button', { name: 'Remover browser-api do scope test.scope', exact: true }).waitFor();
    await page.getByRole('searchbox', { name: 'Pesquisar audiências' }).fill('no-such-audience');
    await page.getByText('Nenhuma audiência encontrada', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Limpar pesquisa', exact: true }).click();
    await page.getByRole('button', { name: 'Remover browser-api do scope test.scope', exact: true }).click();
    await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
    await assertInventoryFocus();
    await page.getByRole('button', { name: 'Remover browser-api do scope test.scope', exact: true }).click();
    await page.getByRole('button', { name: 'Confirmar remoção', exact: true }).click();
    await page.getByRole('status').filter({ hasText: 'Vínculo removido.' }).waitFor();
    await assertInventoryFocus();
    assert.equal(await page.getByRole('button', { name: 'Remover browser-api do scope test.scope', exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Vincular audiência', exact: true }).click();
    await page.getByLabel('Identificador da audiência', { exact: true }).fill('reject-test');
    await selectScope();
    await page.getByRole('button', { name: 'Salvar vínculo', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Vínculo não alterado' }).waitFor();
    assert.equal(await page.getByLabel('Identificador da audiência', { exact: true }).inputValue(), 'reject-test');
    await page.getByRole('button', { name: 'Atualizar para revisar', exact: true }).click();
    await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
    await assertInventoryFocus();
    await page.getByRole('button', { name: 'Vincular audiência', exact: true }).click();
    await page.getByLabel('Identificador da audiência', { exact: true }).fill('SufficitEndpointsIntrospection');
    await selectScope();
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
        await page.setViewportSize({ width, height });
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({ path: path.join(output, `${name}.png`), fullPage: true, animations: 'disabled' });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${name}: horizontal page overflow`);
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${origin}/management/settings/trusted-proxies`);
    const active = page.locator('a.nav-item.active');
    assert.equal(await active.count(), 1);
    assert.equal(await active.getAttribute('href'), 'settings/trusted-proxies');
    await page.goto(`${origin}/management/audiences`);
    await page.getByRole('button', { name: 'Vincular audiência', exact: true }).click();
    await page.getByLabel('Identificador da audiência', { exact: true }).fill('fail-list-test');
    await selectScope();
    await page.getByRole('button', { name: 'Salvar vínculo', exact: true }).click();
    await page.getByText('Nenhum resultado carregado', { exact: true }).waitFor();
    await assertInventoryFocus();
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
        await page.setViewportSize({ width, height });
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({ path: path.join(output, `${name}-failure.png`), fullPage: true, animations: 'disabled' });
    }
    assert.deepEqual(failures, []);
    console.log('Passed: add/remove/cancel, keyboard focus, search/empty, conflict/review, unavailable inventory, menu and desktop/mobile overflow.');
} finally {
    await browser.close();
}
