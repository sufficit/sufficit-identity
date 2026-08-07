using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class ConsentFallbackIntegrationTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public ConsentFallbackIntegrationTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Theory]
    [InlineData(null)]
    [InlineData("legacy-unknown")]
    public async Task Missing_or_unknown_stored_consent_type_redirects_to_consent(
        string? storedConsentType)
    {
        var suffix = Guid.NewGuid().ToString("N");
        var clientId = $"consent-fallback-{suffix}";
        var redirectUri = $"https://client.tests.local/consent-fallback/{suffix}";
        var username = $"consent-fallback-{suffix}";

        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Explicit,
                RedirectUris = { new Uri(redirectUri) },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange,
                },
            });

            var database = services.GetRequiredService<AppDbContext>();
            var application = await database
                .Set<OpenIddictEntityFrameworkCoreApplication>()
                .SingleAsync(candidate => candidate.ClientId == clientId);
            application.ConsentType = storedConsentType;
            await database.SaveChangesAsync();

            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(
                users,
                username,
                "Str0ng!Passw0rd#ConsentFallback");
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var (_, challenge) = Pkce.CreatePair();

        var authorizeUri = QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = clientId,
                ["redirect_uri"] = redirectUri,
                ["scope"] = "openid",
                ["state"] = Guid.NewGuid().ToString("N"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(authorizeUri);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location?.OriginalString
            ?? throw new InvalidOperationException("No consent redirect Location header.");
        Assert.StartsWith("/consent?", location, StringComparison.Ordinal);
        var query = QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
        Assert.Equal(clientId, query["client_id"].ToString());
    }
}
