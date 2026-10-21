using System.Globalization;
using Sufficit.Identity.UI.Components.Dates;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Instants render in the reader's zone and culture, not the server's.
/// </summary>
public sealed class BrowserTimeTests
{
    private static readonly DateTimeOffset Instant = new(2026, 10, 21, 13, 7, 20, TimeSpan.Zero);

    [Fact]
    public void Converts_to_the_reader_zone_in_the_reader_culture()
    {
        using var _ = new CultureScope("pt-BR");
        var time = new BrowserTime(TimeZoneInfo.FindSystemTimeZoneById("America/Sao_Paulo"), true);

        Assert.Equal("21/10/2026 10:07", time.Format(Instant));
        Assert.Equal("21/10/2026 10:07:20", time.Format(Instant, TimeStyle.DateTimeSeconds));
        Assert.Equal("21/10", time.Format(Instant, TimeStyle.DayMonth));
        Assert.Equal("10:07", time.Format(Instant, TimeStyle.Time));
    }

    [Fact]
    public void Another_reader_sees_their_own_clock_and_format()
    {
        using var _ = new CultureScope("en-US");
        var time = new BrowserTime(TimeZoneInfo.FindSystemTimeZoneById("Europe/Lisbon"), true);

        // ICU separates "PM" with a narrow no-break space in recent versions.
        Assert.Equal("10/21/2026 2:07 PM", time.Format(Instant).Replace('\u202F', ' '));
        Assert.Equal("10/21", time.Format(Instant, TimeStyle.DayMonth));
    }

    [Fact]
    public void Unspecified_date_times_are_storage_utc()
    {
        using var _ = new CultureScope("pt-BR");
        var time = new BrowserTime(TimeZoneInfo.FindSystemTimeZoneById("America/Sao_Paulo"), true);

        Assert.Equal("21/10/2026 10:07", time.Format(new DateTime(2026, 10, 21, 13, 7, 20)));
        Assert.Null(time.Format((DateTime?)null));
    }

    [Fact]
    public void Unknown_zone_names_fall_back_to_the_browser_offset()
    {
        var zone = BrowserTime.ZoneFor(new BrowserZoneAnswer("Nowhere/Unknown", -180));

        Assert.Equal(TimeSpan.FromHours(-3), zone.GetUtcOffset(Instant));
        Assert.Equal(TimeZoneInfo.Utc, BrowserTime.ZoneFor(new BrowserZoneAnswer(null, 0)));
    }

    [Fact]
    public void Calendar_days_keep_their_date()
    {
        using var _ = new CultureScope("pt-BR");

        Assert.Equal("21/10", BrowserTime.FormatDay(new DateTime(2026, 10, 21), TimeStyle.DayMonth));
    }

    private sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo culture = CultureInfo.CurrentCulture;
        private readonly CultureInfo uiCulture = CultureInfo.CurrentUICulture;

        public CultureScope(string name)
        {
            CultureInfo.CurrentCulture = new CultureInfo(name);
            CultureInfo.CurrentUICulture = new CultureInfo(name);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = uiCulture;
        }
    }
}
