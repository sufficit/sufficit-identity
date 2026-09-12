using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Sufficit.Identity.STS.Resources;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// End-user text the API module renders itself (email messages, the fallback
/// browser error page). Everything else the API returns is English plus a
/// stable code that the presentation module translates.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class ApiLocalizationTests(SufficitIdentityTestFactory factory)
{
    private static readonly Regex PortugueseCharacters = new(
        "[ãõçáéíóúâêôà]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    [Fact]
    public void Neutral_account_messages_are_english_and_every_culture_has_the_same_keys()
    {
        var resources = ResourcesDirectory();
        var neutral = Values(Path.Combine(resources, "AccountMessages.resx"));

        Assert.NotEmpty(neutral);
        Assert.DoesNotContain(
            neutral,
            pair => PortugueseCharacters.IsMatch(pair.Value));

        var satellites = Directory
            .EnumerateFiles(resources, "AccountMessages.*.resx")
            .ToArray();
        Assert.NotEmpty(satellites);
        foreach (var satellite in satellites)
        {
            Assert.Equal(
                neutral.Keys.Order(StringComparer.Ordinal),
                Values(satellite).Keys.Order(StringComparer.Ordinal));
        }
    }

    [Theory]
    [InlineData("en-US", "Confirm your email — Acme")]
    [InlineData("pt-BR", "Confirme seu e-mail — Acme")]
    [InlineData("fr-FR", "Confirm your email — Acme")]
    public void Account_messages_follow_the_request_culture_and_fall_back_to_english(
        string culture,
        string expected)
    {
        var previous = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
            using var scope = factory.Services.CreateScope();
            var messages = scope.ServiceProvider
                .GetRequiredService<IStringLocalizer<AccountMessages>>();

            var subject = messages["ConfirmEmail.Subject", "Acme"];

            Assert.False(subject.ResourceNotFound);
            Assert.Equal(expected, subject.Value);
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    private static Dictionary<string, string> Values(string path) =>
        XDocument.Load(path)
            .Root!
            .Elements("data")
            .ToDictionary(
                element => (string)element.Attribute("name")!,
                element => (string?)element.Element("value") ?? string.Empty,
                StringComparer.Ordinal);

    private static string ResourcesDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(directory!.FullName, "src", "sts", "Resources");
    }
}
