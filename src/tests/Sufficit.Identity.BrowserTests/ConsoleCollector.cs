using Microsoft.Playwright;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Captures Chrome DevTools console output during a page session, filtered
/// by severity. Chrome surfaces issues that server-side tests cannot see:
/// form autofill warnings (missing id/name), CSS preload mismatches, 404
/// resources, CSP violations, and uncaught JavaScript exceptions.
/// </summary>
public sealed class ConsoleCollector : IAsyncDisposable
{
    private readonly IPage _page;
    private readonly List<ConsoleEntry> _entries = [];
    private readonly List<string> _failedRequests = [];




    public ConsoleCollector(IPage page)
    {
        _page = page;
        page.Console += (_, message) =>
        {
            _entries.Add(new ConsoleEntry(
                message.Type,
                message.Text,
                message.Location ?? ""));
        };
        page.RequestFailed += (_, request) =>
        {
            _failedRequests.Add($"{request.Method} {request.Url} — {request.Failure}");
        };
        page.PageError += (_, error) =>
        {
            _entries.Add(new ConsoleEntry(
                "error",
                $"Uncaught exception: {error}",
                _page.Url));
        };
    }

    public IReadOnlyList<ConsoleEntry> Entries => _entries;
    public IReadOnlyList<string> FailedRequests => _failedRequests;

    /// <summary>Console messages of type error.</summary>
    public IReadOnlyList<ConsoleEntry> Errors =>
        _entries.Where(e => e.IsError).ToArray();

    /// <summary>Console messages of type warning (Chrome autofill, preload, deprecation).</summary>
    public IReadOnlyList<ConsoleEntry> Warnings =>
        _entries.Where(e => e.IsWarning).ToArray();

    /// <summary>
    /// Form fields missing id or name — the exact Chrome autofill warning the
    /// browser surfaces in DevTools ("A form field element has neither an id
    /// nor a name attribute"). These prevent correct browser autofill.
    /// </summary>
    public IReadOnlyList<ConsoleEntry> AutofillWarnings =>
        _entries.Where(e =>
            e.IsWarning
            && e.Text.Contains("form field", StringComparison.OrdinalIgnoreCase)
            && (e.Text.Contains("id", StringComparison.OrdinalIgnoreCase)
                || e.Text.Contains("name", StringComparison.OrdinalIgnoreCase)))
        .ToArray();

    /// <summary>
    /// Resources preloaded via link preload but not used — indicates a
    /// preload hint that doesn't match actual usage (wasted bandwidth,
    /// potential CSS scoping issue).
    /// </summary>
    public IReadOnlyList<ConsoleEntry> PreloadWarnings =>
        _entries.Where(e =>
            e.IsWarning
            && e.Text.Contains("preloaded using link preload", StringComparison.OrdinalIgnoreCase))
        .ToArray();

    /// <summary>Network requests that failed (404, network error, aborted).</summary>
    public IReadOnlyList<string> ResourceFailures => _failedRequests;

    public async ValueTask DisposeAsync()
    {
        // Playwright event subscriptions are cleaned up when the page is closed
        await Task.CompletedTask;
    }

    public sealed record ConsoleEntry(
        string Type,
        string Text,
        string Location)
    {
        public bool IsError => Type is "error";
        public bool IsWarning => Type is "warning";
    }
}

/// <summary>
/// Evaluates DOM-level UI health in the browser: form fields without
/// id/name, CSS files that loaded but have no effect, elements with
/// overlapping bounding boxes, and inputs without computed styling.
/// </summary>
public static class DomHealthChecks
{
    /// <summary>
    /// Finds all form fields (input, select, textarea) that lack BOTH id and
    /// name attributes — the same condition Chrome flags as an autofill
    /// warning. Returns a descriptive list for the test assertion message.
    /// </summary>
    public static async Task<IReadOnlyList<string>> GetFormFieldsWithoutIdentityAsync(
        IPage page)
    {
        return await page.EvaluateAsync<IReadOnlyList<string>>("""
            Array.from(document.querySelectorAll('input, select, textarea'))
                .filter(el => {
                    // Skip hidden, submit and button inputs — they don't need autofill identity
                    const type = (el.type || '').toLowerCase();
                    if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'reset') return false;
                    return !el.id && !el.name && !el.getAttribute('name');
                })
                .map(el => {
                    const label = el.closest('label')?.querySelector('span')?.textContent?.trim()
                        ?? el.getAttribute('aria-label')
                        ?? el.getAttribute('placeholder')
                        ?? el.type
                        ?? el.tagName.toLowerCase();
                    return `<${el.tagName.toLowerCase()} type="${el.type}"> in "${label}" — missing id AND name`;
                })
            """);
    }

    /// <summary>
    /// Finds elements whose bounding boxes overlap with a sibling in the same
    /// parent — a visual indicator that CSS layout (grid/flex) is not
    /// applying correctly.
    /// </summary>
    public static async Task<IReadOnlyList<string>> GetOverlappingSiblingsAsync(
        IPage page,
        string containerSelector)
    {
        return await page.EvaluateAsync<IReadOnlyList<string>>($$"""
            (() => {
                const container = document.querySelector('{{containerSelector}}');
                if (!container) return [];
                const children = Array.from(container.children);
                const overlaps = [];
                for (let i = 0; i < children.length; i++) {
                    for (let j = i + 1; j < children.length; j++) {
                        const a = children[i].getBoundingClientRect();
                        const b = children[j].getBoundingClientRect();
                        const horizontalOverlap = Math.min(a.right, b.right) - Math.max(a.left, b.left);
                        const verticalOverlap = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
                        if (horizontalOverlap > 5 && verticalOverlap > 5) {
                            overlaps.push(
                                `"${children[i].className || children[i].tagName}" overlaps ` +
                                `"${children[j].className || children[j].tagName}" ` +
                                `by ${Math.round(horizontalOverlap)}x${Math.round(verticalOverlap)}px`);
                        }
                    }
                }
                return overlaps;
            })()
            """);
    }

    /// <summary>
    /// Verifies that a stylesheet link actually loaded and has rules applied.
    /// Returns the number of CSSRules in the sheet, or -1 if blocked/empty.
    /// </summary>
    public static async Task<int> GetStylesheetRuleCountAsync(
        IPage page,
        string href)
    {
        return await page.EvaluateAsync<int>($$"""
            (() => {
                const link = document.querySelector('link[rel="stylesheet"][href*="{{href}}"]');
                if (!link) return -1;
                if (!link.sheet) return -2;
                try {
                    return link.sheet.cssRules.length;
                } catch {
                    return -3; // CORS or security error
                }
            })()
            """);
    }

    /// <summary>
    /// Finds form controls within a container that have no computed border
    /// or min-height — indicating that CSS is not applying to them.
    /// </summary>
    public static async Task<IReadOnlyList<string>> GetUnstyledFormControlsAsync(
        IPage page,
        string containerSelector)
    {
        return await page.EvaluateAsync<IReadOnlyList<string>>($$"""
            Array.from(document.querySelectorAll('{{containerSelector}} input, {{containerSelector}} select'))
                .filter(el => {
                    const style = getComputedStyle(el);
                    return style.borderStyle === 'none'
                        || style.minHeight === '0px'
                        || style.width === '0px';
                })
                .map(el => {
                    const label = el.closest('label')?.querySelector('span')?.textContent?.trim()
                        ?? el.getAttribute('aria-label')
                        ?? el.name || el.id || el.type;
                    return `<${el.tagName.toLowerCase()} type="${el.type}"> "${label}" — no computed border/min-height`;
                })
            """);
    }
}
