using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.STS.Jar;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Every way a request object is refused, asserted on the reason rather than
/// on the status code. The integration test beside this one covered the
/// accepted path and a replay whose refusal it accepted as any 400 — a request
/// refused for a different reason would have passed it.
/// </summary>
public sealed class JarRequestObjectRefusalTests : IAsyncLifetime
{
    private const string ClientId = "jar-refusal-client";
    private const string OtherClientId = "jar-refusal-other-client";
    private const string Issuer = "https://sts.tests.local/";

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private ECDsaSecurityKey _otherSigningKey = null!;
    private SufficitIdentityTestFactory _factory = null!;
    private ECDsaSecurityKey _signingKey = null!;

    public async Task InitializeAsync()
    {
        _factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jar:Enabled"] = "true",
            });
        await ((IAsyncLifetime)_factory).InitializeAsync();

        _signingKey = new ECDsaSecurityKey(_key) { KeyId = "refusal-key" };
        _otherSigningKey = new ECDsaSecurityKey(_otherKey) { KeyId = "other-key" };

        using var scope = _factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await Register(applications, ClientId, _signingKey);
        await Register(applications, OtherClientId, _otherSigningKey);

        static async Task Register(
            IOpenIddictApplicationManager applications,
            string clientId,
            ECDsaSecurityKey key)
        {
            var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
            publicJwk.D = null;
            publicJwk.Use = "sig";
            publicJwk.KeyId = key.KeyId;
            var keySet = new JsonWebKeySet();
            keySet.Keys.Add(publicJwk);
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ClientSecret = clientId + "-secret",
                RedirectUris = { new Uri("https://client.tests.local/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                },
                JsonWebKeySet = keySet,
            });
        }
    }

    public Task DisposeAsync()
    {
        _factory.Dispose();
        _key.Dispose();
        _otherKey.Dispose();
        return Task.CompletedTask;
    }

    private string RequestObject(
        string? tokenType = "oauth-authz-req+jwt",
        bool issuedAt = true,
        bool expires = true,
        TimeSpan? lifetime = null,
        string? jti = "set-per-call",
        DateTime? issuedAtValue = null,
        bool asOtherClient = false)
    {
        var clientId = asOtherClient ? OtherClientId : ClientId;
        var now = issuedAtValue ?? DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = "https://client.tests.local/callback",
            ["scope"] = "openid",
        };
        if (jti is not null)
        {
            claims["jti"] = jti == "set-per-call" ? Guid.NewGuid().ToString("N") : jti;
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = Issuer,
            IssuedAt = issuedAt ? now : null,
            Expires = expires ? now + (lifetime ?? TimeSpan.FromMinutes(1)) : null,
            TokenType = tokenType,
            SigningCredentials = new SigningCredentials(
                asOtherClient ? _otherSigningKey : _signingKey,
                SecurityAlgorithms.EcdsaSha256),
            Claims = claims,
        });
    }

    private async Task<string?> RefusalOf(
        string requestObject,
        bool asOtherClient = false)
    {
        using var scope = _factory.Services.CreateScope();
        var services = scope.ServiceProvider;
        var request = new OpenIddictRequest
        {
            ClientId = asOtherClient ? OtherClientId : ClientId,
            Request = requestObject,
        };

        string? refusal = null;
        await JarExtractor.TryMergeAsync(
            request,
            services.GetRequiredService<IOpenIddictApplicationManager>(),
            services.GetRequiredService<IJarSigningKeyResolver>(),
            services.GetRequiredService<SufficitIdentityOptions>().Jar,
            Issuer,
            services.GetRequiredService<IDpopReplayCache>(),
            NullLogger.Instance,
            (description, _) => refusal ??= description,
            CancellationToken.None);
        return refusal;
    }

    [Fact]
    public async Task A_well_formed_request_object_is_accepted()
    {
        // The baseline the refusals below are measured against: without it, a
        // harness that refused everything would pass every one of them.
        Assert.Null(await RefusalOf(RequestObject()));
    }

    [Theory]
    [InlineData("JWT")]
    [InlineData("dpop+jwt")]
    public async Task A_request_object_of_another_type_is_refused(string tokenType) =>
        Assert.Equal(
            "The request object typ must be 'oauth-authz-req+jwt'.",
            await RefusalOf(RequestObject(tokenType: tokenType)));

    [Fact]
    public async Task A_request_object_missing_iat_is_refused() =>
        Assert.Equal(
            "The request object must contain valid iat, exp and jti claims.",
            await RefusalOf(RequestObject(issuedAt: false)));

    [Fact]
    public async Task A_request_object_missing_exp_is_refused() =>
        Assert.Equal(
            "The request object must contain valid iat, exp and jti claims.",
            await RefusalOf(RequestObject(expires: false)));

    [Fact]
    public async Task A_request_object_missing_jti_is_refused() =>
        Assert.Equal(
            "The request object must contain valid iat, exp and jti claims.",
            await RefusalOf(RequestObject(jti: null)));

    [Fact]
    public async Task A_request_object_living_longer_than_allowed_is_refused() =>
        // Default maximum is 120 seconds.
        Assert.Equal(
            "The request object lifetime is outside the allowed window.",
            await RefusalOf(RequestObject(lifetime: TimeSpan.FromMinutes(10))));

    [Fact]
    public async Task A_request_object_issued_in_the_future_is_refused() =>
        Assert.Equal(
            "The request object lifetime is outside the allowed window.",
            await RefusalOf(RequestObject(
                issuedAtValue: DateTime.UtcNow.AddMinutes(5))));

    [Fact]
    public async Task A_request_object_is_refused_the_second_time()
    {
        var requestObject = RequestObject(jti: "replayed-once");

        Assert.Null(await RefusalOf(requestObject));
        Assert.Equal(
            "The request object has already been used.",
            await RefusalOf(requestObject));
    }

    [Fact]
    public async Task A_jti_is_scoped_to_its_client()
    {
        // The replay key is "jar:<client>:<jti>". If it were the jti alone, a
        // client could burn another client's request ids by sending them first
        // — a denial of service needing nothing but a guess at the format.
        Assert.Null(await RefusalOf(
            RequestObject(jti: "shared-looking-id", asOtherClient: true),
            asOtherClient: true));

        // The same id from a different client is still fresh.
        Assert.Null(await RefusalOf(RequestObject(jti: "shared-looking-id")));

        // And each client's own second use is still a replay.
        Assert.Equal(
            "The request object has already been used.",
            await RefusalOf(RequestObject(jti: "shared-looking-id")));
    }
}
