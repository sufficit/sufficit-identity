using System.Text.Json;
using Microsoft.Playwright;

namespace Sufficit.Identity.BrowserTests;

public sealed class ConsoleCollector : IAsyncDisposable
{
    private readonly IPage _page;
    private readonly List<ConsoleEntry> _entries = [];
    private readonly List<string> _failedRequests = [];

    public ConsoleCollector(IPage page)
    {
        _page = page;
        page.Console += (_, m) => { _entries.Add(new(m.Type, m.Text, m.Location ?? "")); };
        page.RequestFailed += (_, r) => { _failedRequests.Add(r.Method + " " + r.Url + " - " + r.Failure); };
        page.PageError += (_, e) => { _entries.Add(new("error", "Uncaught: " + e, _page.Url)); };
    }

    public IReadOnlyList<ConsoleEntry> Entries => _entries;
    public IReadOnlyList<ConsoleEntry> Errors => _entries.Where(e => e.IsError && !IsDevNoise(e.Text)).ToArray();
    public IReadOnlyList<ConsoleEntry> Warnings => _entries.Where(e => e.IsWarning).ToArray();
    public IReadOnlyList<ConsoleEntry> AutofillWarnings => Warnings.Where(e => e.Text.Contains("form field", StringComparison.OrdinalIgnoreCase)).ToArray();
    public IReadOnlyList<ConsoleEntry> PreloadWarnings => Warnings.Where(e => e.Text.Contains("preloaded using link preload", StringComparison.OrdinalIgnoreCase)).ToArray();
    public IReadOnlyList<string> ResourceFailures => _failedRequests.Where(r => !r.Contains("ERR_CONTENT_DECODING_FAILED", StringComparison.OrdinalIgnoreCase)).ToArray();

    private static bool IsDevNoise(string text) =>
        text.Contains("ERR_CONTENT_DECODING_FAILED", StringComparison.OrdinalIgnoreCase)
        || text.Contains("net::ERR", StringComparison.OrdinalIgnoreCase);

    public async ValueTask DisposeAsync() => await Task.CompletedTask;
    public sealed record ConsoleEntry(string Type, string Text, string Location)
    {
        public bool IsError => Type is "error";
        public bool IsWarning => Type is "warning";
    }
}

public static class DomHealthChecks
{
    private static async Task<string[]> Eval(IPage page, string js)
    {
        var json = await page.EvaluateAsync<string>("JSON.stringify(" + js + ")");
        return JsonSerializer.Deserialize<string[]>(json) ?? [];
    }

    public static async Task<string[]> GetFormFieldsWithoutIdentityAsync(IPage page) =>
        await Eval(page,
            "Array.from(document.querySelectorAll('input,select,textarea'))" +
            ".filter(el=>{const t=(el.type||'').toLowerCase();" +
            "if(['hidden','submit','button','reset'].includes(t))return false;" +
            "return !el.id&&!el.name;})" +
            ".map(el=>el.tagName+' type='+el.type+' missing id/name')");

    public static async Task<string[]> GetOverlappingSiblingsAsync(IPage page, string sel) =>
        await Eval(page,
            "(()=>{const c=document.querySelector('" + sel + "');if(!c)return[];" +
            "const ch=Array.from(c.children);const o=[];" +
            "for(let i=0;i<ch.length;i++)for(let j=i+1;j<ch.length;j++){" +
            "const a=ch[i].getBoundingClientRect(),b=ch[j].getBoundingClientRect();" +
            "const h=Math.min(a.right,b.right)-Math.max(a.left,b.left);" +
            "const v=Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top);" +
            "if(h>5&&v>5)o.push(ch[i].className+' overlaps '+ch[j].className+' '+Math.round(h)+'x'+Math.round(v)+'px');}" +
            "return o;})()");

    public static async Task<int> GetStylesheetRuleCountAsync(IPage page, string frag) =>
        await page.EvaluateAsync<int>(
            "(()=>{const l=document.querySelector(\"link[rel='stylesheet'][href*='" + frag + "']\");" +
            "if(!l||!l.sheet)return 0;try{return l.sheet.cssRules.length;}catch{return 0;}})()");

    /// <summary>
    /// Inputs/selects inside the container that render with browser defaults.
    /// An element counts as styled when it has its own border/min-height OR
    /// sits inside a wrapper that carries them (pill-search pattern: the
    /// wrapper draws the border, the inner input is transparent on purpose).
    /// </summary>
    public static async Task<string[]> GetUnstyledFormControlsAsync(IPage page, string sel) =>
        await Eval(page,
            "Array.from(document.querySelectorAll('" + sel + " input," + sel + " select'))" +
            ".filter(el=>{" +
            "const own=getComputedStyle(el);" +
            "if(own.borderStyle!=='none'&&own.minHeight!=='0px')return false;" +
            "const w=el.closest('[class]');if(!w)return true;" +
            "const ws=getComputedStyle(w);" +
            "return ws.borderStyle==='none'||ws.minHeight==='0px';})" +
            ".map(el=>el.tagName+' '+el.type+' unstyled')");
}
