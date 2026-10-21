using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.JSInterop;

namespace Sufficit.Identity.UI.Components.Dates;

/// <summary>How much of an instant to show; patterns come from the UI culture.</summary>
public enum TimeStyle
{
    /// <summary>Short date ("d").</summary>
    Date,
    /// <summary>Short date and time ("g").</summary>
    DateTime,
    /// <summary>Short date and time with seconds ("G").</summary>
    DateTimeSeconds,
    /// <summary>Time only ("t").</summary>
    Time,
    /// <summary>Day and month, the culture's short date without the year.</summary>
    DayMonth,
    /// <summary>Day, month and time.</summary>
    DayMonthTime,
    /// <summary>Day, month and time with seconds.</summary>
    DayMonthTimeSeconds,
}

/// <summary>
/// Formats instants in the reader's time zone and UI culture. Identity data
/// is stored in UTC; <see cref="System.DateTime.ToLocalTime"/> would use the
/// server's zone, right only where server and readers share one.
/// Until the browser answers (prerendering, first paint) the server zone is
/// used, so nothing renders blank; <see cref="Resolved"/> tells them apart.
/// </summary>
public sealed partial record BrowserTime(TimeZoneInfo Zone, bool Resolved)
{
    private const string ModulePath = "./_content/Sufficit.Identity.UI.Components/browser-time.js";

    /// <summary>The fallback before the browser zone is known.</summary>
    public static BrowserTime Server { get; } = new(TimeZoneInfo.Local, false);

    /// <summary>Asks the browser for its zone; returns <see cref="Server"/> when it cannot answer.</summary>
    public static async Task<BrowserTime> ResolveAsync(IJSRuntime js)
    {
        try
        {
            await using var module = await js.InvokeAsync<IJSObjectReference>("import", ModulePath);
            var answer = await module.InvokeAsync<BrowserZoneAnswer>("timeZone");
            return new BrowserTime(ZoneFor(answer), true);
        }
        catch (JSException) { return Server; }
        catch (JSDisconnectedException) { return Server; }
        catch (InvalidOperationException) { return Server; } // prerendering: no JS yet
        catch (TaskCanceledException) { return Server; }
    }

    internal static TimeZoneInfo ZoneFor(BrowserZoneAnswer answer)
    {
        if (!string.IsNullOrWhiteSpace(answer.Name)
            && TimeZoneInfo.TryFindSystemTimeZoneById(answer.Name, out var zone))
            return zone;
        var offset = TimeSpan.FromMinutes(Math.Clamp(answer.OffsetMinutes, -14 * 60, 14 * 60));
        return offset == TimeSpan.Zero
            ? TimeZoneInfo.Utc
            : TimeZoneInfo.CreateCustomTimeZone($"browser{offset:hhmm}", offset, null, null);
    }

    /// <summary>Formats an instant in this zone and the current UI culture.</summary>
    public string Format(DateTimeOffset value, TimeStyle style = TimeStyle.DateTime)
    {
        var culture = CultureInfo.CurrentCulture;
        var local = TimeZoneInfo.ConvertTime(value, Zone);
        return local.ToString(Pattern(style, culture.DateTimeFormat), culture);
    }

    /// <summary>
    /// Formats a <see cref="System.DateTime"/>. Values without a kind are
    /// treated as UTC, the storage convention; local-kind values are
    /// converted from the server zone.
    /// </summary>
    public string Format(DateTime value, TimeStyle style = TimeStyle.DateTime) =>
        Format(value.Kind switch
        {
            DateTimeKind.Local => new DateTimeOffset(value),
            _ => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)),
        }, style);

    /// <summary>Null-tolerant overload.</summary>
    public string? Format(DateTimeOffset? value, TimeStyle style = TimeStyle.DateTime) =>
        value is { } v ? Format(v, style) : null;

    /// <summary>Null-tolerant overload.</summary>
    public string? Format(DateTime? value, TimeStyle style = TimeStyle.DateTime) =>
        value is { } v ? Format(v, style) : null;

    /// <summary>
    /// Formats a calendar day without moving it between zones: for values that
    /// are days already (UTC aggregation buckets), not instants.
    /// </summary>
    public static string FormatDay(DateTime day, TimeStyle style = TimeStyle.Date)
    {
        var culture = CultureInfo.CurrentCulture;
        return day.ToString(Pattern(style, culture.DateTimeFormat), culture);
    }

    /// <summary>Calendar-day overload of <see cref="FormatDay(DateTime, TimeStyle)"/>.</summary>
    public static string FormatDay(DateOnly day, TimeStyle style = TimeStyle.Date) =>
        FormatDay(day.ToDateTime(TimeOnly.MinValue), style);

    internal static string Pattern(TimeStyle style, DateTimeFormatInfo format) => style switch
    {
        TimeStyle.Date => format.ShortDatePattern,
        TimeStyle.DateTime => format.ShortDatePattern + " " + format.ShortTimePattern,
        TimeStyle.DateTimeSeconds => format.ShortDatePattern + " " + format.LongTimePattern,
        TimeStyle.Time => format.ShortTimePattern,
        TimeStyle.DayMonth => DayMonth(format.ShortDatePattern),
        TimeStyle.DayMonthTime => DayMonth(format.ShortDatePattern) + " " + format.ShortTimePattern,
        TimeStyle.DayMonthTimeSeconds => DayMonth(format.ShortDatePattern) + " " + format.LongTimePattern,
        _ => format.ShortDatePattern,
    };

    // "dd/MM/yyyy" → "dd/MM", "M/d/yyyy" → "M/d", "yyyy-MM-dd" → "MM-dd".
    private static string DayMonth(string shortDate)
    {
        var withoutYear = YearPart().Replace(shortDate, string.Empty);
        return string.IsNullOrWhiteSpace(withoutYear) ? shortDate : withoutYear;
    }

    [GeneratedRegex(@"^y+[^dMy]*|[^dMy]*y+$")]
    private static partial Regex YearPart();
}

/// <summary>Shape returned by browser-time.js.</summary>
public sealed record BrowserZoneAnswer(string? Name, int OffsetMinutes);
