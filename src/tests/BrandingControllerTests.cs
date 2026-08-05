using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class BrandingControllerTests
{
    [Fact]
    public async Task Create_normalizes_relative_assets_and_rejects_invalid_values()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = Theme($"Theme {Guid.NewGuid():N}");
        request.LogoUrl = "_content/Sufficit.Identity.UI/img/logo-full.png";

        using var created = await client.PostAsJsonAsync("/api/branding", request);
        var theme = await created.Content
            .ReadFromJsonAsync<ManagementBrandingTheme>();

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.NotNull(theme);
        Assert.Equal(
            "/_content/Sufficit.Identity.UI/img/logo-full.png",
            theme.LogoUrl);
        Assert.False(theme.IsActive);

        request.BrandColor = "red";
        request.LogoUrl = "javascript:alert(1)";
        using var invalid = await client.PostAsJsonAsync(
            "/api/branding",
            request);

        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Fact]
    public async Task Activate_repairs_multiple_active_themes_and_mutations_are_audited()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var first = await CreateAsync(client, $"First {Guid.NewGuid():N}");
        var second = await CreateAsync(client, $"Second {Guid.NewGuid():N}");

        using var firstActivation = await client.PutAsync(
            $"/api/branding/{first.Id}/activate",
            content: null);
        Assert.Equal(HttpStatusCode.OK, firstActivation.StatusCode);

        // Simulate legacy drift that predates the canonical application
        // boundary: two rows marked active at once.
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider
                .GetRequiredService<AppDbContext>();
            var legacySecond = await database.BrandingThemes
                .SingleAsync(theme => theme.Id == second.Id);
            legacySecond.IsActive = true;
            await database.SaveChangesAsync();
        }

        using var repaired = await client.PutAsync(
            $"/api/branding/{second.Id}/activate",
            content: null);
        Assert.Equal(HttpStatusCode.OK, repaired.StatusCode);

        using var activeDelete = await client.DeleteAsync(
            $"/api/branding/{second.Id}");
        Assert.Equal(HttpStatusCode.Conflict, activeDelete.StatusCode);

        using var inactiveDelete = await client.DeleteAsync(
            $"/api/branding/{first.Id}");
        Assert.Equal(HttpStatusCode.NoContent, inactiveDelete.StatusCode);

        await using var verificationScope = factory.Services.CreateAsyncScope();
        var verificationDatabase = verificationScope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var activeThemes = await verificationDatabase.BrandingThemes
            .Where(theme => theme.IsActive)
            .ToArrayAsync();
        var auditEvents = await verificationDatabase.ManagementAuditEvents
            .Where(entry =>
                entry.Capability == "identity.branding.manage")
            .OrderBy(entry => entry.Id)
            .ToArrayAsync();

        Assert.Single(activeThemes);
        Assert.Equal(second.Id, activeThemes[0].Id);
        Assert.Contains(
            auditEvents,
            entry => entry.ResourceId == second.Id.ToString()
                && entry.ReasonCode == "branding_activated"
                && entry.OperationOutcome == "succeeded");
        Assert.Contains(
            auditEvents,
            entry => entry.ResourceId == first.Id.ToString()
                && entry.ReasonCode == "branding_deleted"
                && entry.OperationOutcome == "succeeded");
        Assert.Contains(
            auditEvents,
            entry => entry.ResourceId == second.Id.ToString()
                && entry.ReasonCode == "branding_active_cannot_be_deleted"
                && entry.OperationOutcome == "conflict");
    }

    private static BrandingRequest Theme(string name) =>
        new()
        {
            Name = name,
            LogoUrl = "/_content/Sufficit.Identity.UI/img/logo-full.png",
            FaviconUrl = "/_content/Sufficit.Identity.UI/img/favicon.png",
            HeaderIconUrl =
                "/_content/Sufficit.Identity.UI/img/header-icon.png",
            BackgroundImageUrl =
                "/_content/Sufficit.Identity.UI/img/login-bg.jpg",
            BrandColor = "#cc0000",
            BrandHoverColor = "#a30000",
            BrandSoftColor = "#fbe9e9",
            ThemeColor = "#cc0000",
            Title = "Test Identity",
            BrandName = "Test",
            BrandSubtitle = "Identity"
        };

    private static async Task<ManagementBrandingTheme> CreateAsync(
        HttpClient client,
        string name)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/branding",
            Theme(name));
        response.EnsureSuccessStatusCode();
        return (await response.Content
            .ReadFromJsonAsync<ManagementBrandingTheme>())!;
    }
}
