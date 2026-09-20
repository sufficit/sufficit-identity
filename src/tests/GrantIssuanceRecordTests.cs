using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// B1: a grant that authorized issuance is recorded, the way a privileged
/// mint is. The two instruments are separate on purpose — a privileged mint
/// records a token that exists, a grant records the decision OpenIddict then
/// turns into a token set.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class GrantIssuanceRecordTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public GrantIssuanceRecordTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task Each_grant_records_its_own_type()
    {
        var grantTypes = new List<object?>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Name == "identity.security.grant_tokens.issued")
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags.ToArray())
            {
                if (tag.Key == "grant_type")
                {
                    grantTypes.Add(tag.Value);
                }
            }
        });
        listener.Start();

        var client = _factory.CreateClient();

        using var password = await PostAsync(client, new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, password.StatusCode);

        using var clientCredentials = await PostAsync(client,
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        Assert.Equal(HttpStatusCode.OK, clientCredentials.StatusCode);

        Assert.Contains("password", grantTypes);
        Assert.Contains("client_credentials", grantTypes);
    }

    [Fact]
    public void Signing_in_through_the_boundary_always_stamps_destinations()
    {
        // A claim with no destination reaches no token at all. Every grant
        // used to stamp destinations itself, one line before building its
        // own SignInResult; going through the shared boundary is what makes
        // forgetting it unreachable.
        using var scope = _factory.Services.CreateScope();
        var operations = scope.ServiceProvider
            .GetRequiredService<Sufficit.Identity.STS.Grants.GrantOperations>();

        var identity = new ClaimsIdentity(
            "test", OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Role);
        identity.SetClaim(OpenIddictConstants.Claims.Subject, "subject-1");
        identity.SetScopes(TestDataSeeder.ScopeName);

        var result = operations.SignIn(
            identity,
            new OpenIddictRequest { GrantType = "password" });

        var subject = result.Principal!.FindFirst(OpenIddictConstants.Claims.Subject)!;
        Assert.NotEmpty(subject.GetDestinations());
    }

    private static Task<HttpResponseMessage> PostAsync(
        HttpClient client,
        Dictionary<string, string> form) =>
        client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
}
