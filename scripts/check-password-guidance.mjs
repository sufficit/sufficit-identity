// Non-submitting browser checks against the actual password forms.
// Usage: IDENTITY_PLAYWRIGHT_PACKAGE=/path/to/package.json node
// scripts/check-password-guidance.mjs <page-url> [page-url ...]
// URLs may target isolated change/reset fixtures; public registration also works.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(process.env.IDENTITY_PLAYWRIGHT_PACKAGE || import.meta.url);
const { chromium } = require('playwright');
const urls = process.argv.slice(2);
assert.ok(urls.length, 'Supply at least one page URL');
const browser = await chromium.launch({ headless: true });
try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    for (const [index, url] of urls.entries()) {
        const origin = new URL(url).origin;
        await context.addCookies([{ name: '.AspNetCore.Culture', value: 'c=pt-BR|uic=pt-BR', url: origin }]);
        await page.goto(url);
        const guidance = page.locator('#password-requirements');
        await guidance.waitFor();
        const field = page.locator('#' + await guidance.getAttribute('data-password-requirements'));
        const visibleRules = () => guidance.locator('[data-password-rule]:visible');
        const expectPending = async expected => {
            await page.waitForFunction(count => document.querySelectorAll(
                '[data-password-rule]:not([hidden])').length === count, expected);
            assert.equal(await visibleRules().count(), expected);
        };
        assert.match(await guidance.innerText(), /8(?: a 100)? caracteres/);
        assert.ok((await field.getAttribute('aria-describedby')).includes('password-requirements'));
        await field.fill('');
        await expectPending(5);
        await field.pressSequentially('a');
        await expectPending(4);
        await field.pressSequentially('B');
        await expectPending(3);
        await field.pressSequentially('3');
        await expectPending(2);
        await field.pressSequentially('!');
        await expectPending(1);
        assert.match(await visibleRules().innerText(), /caracteres/);
        // Current and confirmation passwords must never control the guidance.
        for (const other of ['#current-password', '#confirm-password', '#confirm']) {
            if (await page.locator(other).count()) await page.locator(other).fill('Unrelated!9');
        }
        await expectPending(1);
        await field.focus();
        await field.press('End');
        await page.keyboard.insertText('xyZ9'); // Paste-like insertion, exactly 8.
        await expectPending(0);
        assert.equal(await guidance.isVisible(), false);
        assert.equal(await field.inputValue(), 'aB3!xyZ9');
        await field.press('Backspace');
        await expectPending(1);
        await field.fill('abcdefgh');
        await expectPending(3);
        assert.match(await guidance.innerText(), /maiúscula/);
        assert.doesNotMatch(await guidance.innerText(), /minúscula/);
        await page.setViewportSize({ width: 390, height: 844 });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.screenshot({ path: `/tmp/password-pending-${index}-mobile.png`, fullPage: true });
        // Password managers may signal change instead of input.
        await field.evaluate(element => {
            element.value = 'Qx7!mZ2p';
            element.dispatchEvent(new Event('change', { bubbles: true }));
        });
        await expectPending(0);
        if (await guidance.getAttribute('data-password-maximum')) {
            await field.fill('Qx7!' + 'x'.repeat(97));
            await expectPending(1);
            assert.match(await visibleRules().innerText(), /100/);
        }
        await field.fill('');
        await expectPending(5);
        await page.setViewportSize({ width: 1440, height: 1000 });
        console.log(`PASS page ${index + 1}: pending rules, typing/paste/change, deletion, unrelated fields, maximum, mobile`);
    }
    assert.deepEqual(failures, []);
} finally {
    await browser.close();
}
