using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// B1: every privileged token gets its protocol shape from one place.
/// Personal tokens build their own identity — they project live user state,
/// which no flat mint request can express — so they used to carry a second
/// copy of these rules. These tests pin what the shared scaffolding applies,
/// so the next protocol change cannot land on one surface only.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class PrivilegedTokenScaffoldingTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public PrivilegedTokenScaffoldingTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task Scaffolding_stamps_scopes_audience_lifetime_and_issuer()
    {
        var created = DateTimeOffset.UtcNow;
        var expires = created.AddHours(2);

        var identity = await ScaffoldAsync(new PrivilegedTokenScaffold(
            [TestDataSeeder.ScopeName],
            "https://identity.example/",
            created,
            expires));

        Assert.Equal([TestDataSeeder.ScopeName], identity.GetScopes().ToArray());
        Assert.Equal(TestDataSeeder.ScopeName, identity.GetClaim(Claims.Scope));
        Assert.Equal("https://identity.example/",
            identity.GetClaim(Claims.Private.Issuer));
        Assert.Equal(created.ToUnixTimeSeconds(),
            identity.GetCreationDate()!.Value.ToUnixTimeSeconds());
        Assert.Equal(expires.ToUnixTimeSeconds(),
            identity.GetExpirationDate()!.Value.ToUnixTimeSeconds());

        // Resources are resolved from the granted scopes and materialized as
        // BOTH the private resource set and the public audience claim: a
        // reference token is introspected, and introspection identifies the
        // resource servers from the audience.
        var resources = identity.GetResources();
        Assert.Contains(TestDataSeeder.IntrospectionClientId, resources);
        Assert.Equal(
            resources.Order(StringComparer.Ordinal),
            identity.GetClaims(Claims.Audience).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Scaffolding_replaces_protocol_claims_the_caller_left_behind()
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        // A caller that built its identity from an earlier decision, or
        // copied one from another token: the stale scope, audience and
        // issuer must not survive into the minted token.
        identity.SetClaim(Claims.Scope, "stale.scope");
        identity.SetClaims(Claims.Audience, ["stale-audience"]);
        identity.SetClaim(Claims.Private.Issuer, "https://stale.example/");

        await ScaffoldAsync(
            new PrivilegedTokenScaffold(
                [TestDataSeeder.ScopeName],
                "https://identity.example/",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddHours(1)),
            identity);

        Assert.Equal(TestDataSeeder.ScopeName, identity.GetClaim(Claims.Scope));
        Assert.Equal("https://identity.example/",
            identity.GetClaim(Claims.Private.Issuer));
        Assert.DoesNotContain("stale-audience", identity.GetClaims(Claims.Audience));
    }

    [Fact]
    public async Task Default_destinations_keep_a_reference_token_out_of_id_tokens()
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, "subject-1");

        await ScaffoldAsync(
            new PrivilegedTokenScaffold(
                [TestDataSeeder.ScopeName],
                "https://identity.example/",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddHours(1)),
            identity);

        var subject = identity.FindFirst(Claims.Subject)!;
        Assert.Equal([Destinations.AccessToken], subject.GetDestinations().ToArray());
    }

    [Fact]
    public async Task Caller_destinations_are_applied_instead_of_the_default()
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Email, "person@example.test");

        // What a personal token does: a profile claim is released only when
        // the matching scope was granted, which is narrower than the default.
        await ScaffoldAsync(
            new PrivilegedTokenScaffold(
                [TestDataSeeder.ScopeName],
                "https://identity.example/",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddHours(1),
                Resources: null,
                Destinations: claim => claim.Type == Claims.Email
                    ? []
                    : [Destinations.AccessToken]),
            identity);

        Assert.Empty(identity.FindFirst(Claims.Email)!.GetDestinations());
    }

    [Fact]
    public async Task An_explicit_empty_resource_list_mints_an_audience_less_token()
    {
        var identity = await ScaffoldAsync(new PrivilegedTokenScaffold(
            [TestDataSeeder.ScopeName],
            "https://identity.example/",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1),
            Resources: []));

        Assert.Empty(identity.GetResources());
        Assert.Empty(identity.GetClaims(Claims.Audience));
    }

    [Fact]
    public async Task Every_privileged_token_is_recorded_once_by_the_surface_that_minted_it()
    {
        var measurements = new List<IReadOnlyDictionary<string, object?>>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Name
                    == "identity.security.privileged_tokens.minted")
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            measurements.Add(tags.ToArray().ToDictionary(
                tag => tag.Key, tag => tag.Value, StringComparer.Ordinal)));
        listener.Start();

        var client = _factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        using var created = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                description = "issuance-record",
                expiration = DateTimeOffset.UtcNow.AddDays(1),
                scopes = new[] { TestDataSeeder.ScopeName },
            });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var personal = Assert.Single(measurements,
            measurement => Equals(measurement["surface"], "PersonalAccessToken"));
        Assert.Equal(true, personal["reference"]);

        // The subject and the client belong in the log line; a metric tag
        // carrying either would make the instrument unbounded.
        Assert.All(measurements, measurement =>
        {
            Assert.DoesNotContain("subject", measurement.Keys);
            Assert.DoesNotContain("client_id", measurement.Keys);
            Assert.DoesNotContain("token", measurement.Keys);
        });
    }

    private static async Task<string> GetAccessTokenAsync(HttpClient client)
    {
        using var response = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("access_token").GetString()!;
    }

    private async Task<ClaimsIdentity> ScaffoldAsync(
        PrivilegedTokenScaffold scaffold,
        ClaimsIdentity? identity = null)
    {
        identity ??= new ClaimsIdentity("test", Claims.Name, Claims.Role);
        await using var scope = _factory.Services.CreateAsyncScope();
        var minting = scope.ServiceProvider
            .GetRequiredService<IPrivilegedTokenMintingService>();
        await minting.ApplyScaffoldingAsync(identity, scaffold);
        return identity;
    }
}
