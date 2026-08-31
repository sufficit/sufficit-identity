using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS.Jarm;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class FapiJarmTests
{
    [Fact]
    public async Task Jarm_response_signature_issuer_audience_and_lifetime_validate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(key);
        var generator = new JarmResponseGenerator(
            new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local",
            TimeSpan.FromMinutes(2));
        var encoded = generator.Generate(new OpenIddictResponse
        {
            Code = "authorization-code",
            State = "state-123",
        }, "client-123");

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "client-123",
                IssuerSigningKey = securityKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });

        Assert.True(validation.IsValid, validation.Exception?.Message);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);
        Assert.Equal("authorization-code", jwt.GetClaim("code").Value);
        Assert.Equal("state-123", jwt.GetClaim("state").Value);
    }

    [Fact]
    public async Task Jarm_signed_then_encrypted_response_produces_a_five_part_JWE()
    {
        // Signed JARM = 3 compact-serialization parts; signed+encrypted = 5.
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingCredentials = new SigningCredentials(
            new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256);

        // RSA key for JWE encryption (FAPI 2.0 Advancing Profile shape).
        using var rsa = RSA.Create(2048);
        var encryptionRsaKey = new RsaSecurityKey(rsa);
        var encryptionCredentials = new EncryptingCredentials(
            encryptionRsaKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);

        var generator = new JarmResponseGenerator(
            signingCredentials,
            "https://sts.tests.local",
            TimeSpan.FromMinutes(2),
            encryptionCredentials);

        var encoded = generator.Generate(new OpenIddictResponse
        {
            Code = "enc-auth-code",
        }, "client-jwe");

        // A JWE has 5 dot-separated parts; a JWS has 3.
        Assert.Equal(5, encoded.Split('.').Length);

        // Decrypt + validate the inner signed JWT.
        var handler = new JsonWebTokenHandler();
        var decryption = await handler.ValidateTokenAsync(encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "client-jwe",
                IssuerSigningKey = new ECDsaSecurityKey(signingKey),
                TokenDecryptionKey = encryptionRsaKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });
        Assert.True(decryption.IsValid, decryption.Exception?.Message);
    }

    [Fact]
    public async Task Jarm_encryption_resolves_the_recipient_public_key_per_client()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
                ["Sufficit:Identity:Jarm:Encryption:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var rsa = RSA.Create(2048);
        var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(rsa) { KeyId = "client-encryption-key" });
        publicJwk.D = null;
        publicJwk.DP = null;
        publicJwk.DQ = null;
        publicJwk.P = null;
        publicJwk.Q = null;
        publicJwk.QI = null;
        publicJwk.Use = "enc";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "jarm-encryption-client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            JsonWebKeySet = keySet,
        });
        var resolver = scope.ServiceProvider.GetRequiredService<
            IJarmClientEncryptionCredentialsResolver>();

        var credentials = await resolver.ResolveAsync(
            "jarm-encryption-client");
        var missing = await resolver.ResolveAsync("missing-client");

        Assert.NotNull(credentials);
        Assert.Equal("client-encryption-key", credentials.Key.KeyId);
        Assert.Null(missing);
    }

    [Fact]
    public async Task Jarm_encryption_resolves_ec_recipient_with_ecdh_key_management()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
                ["Sufficit:Identity:Jarm:Encryption:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(ec) { KeyId = "client-ec-encryption-key" });
        publicJwk.Use = "enc";
        publicJwk.D = null;

        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "jarm-ec-encryption-client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            JsonWebKeySet = keySet,
        });

        var resolver = scope.ServiceProvider.GetRequiredService<
            IJarmClientEncryptionCredentialsResolver>();
        var credentials = await resolver.ResolveAsync("jarm-ec-encryption-client");

        Assert.NotNull(credentials);
        Assert.Equal("client-ec-encryption-key", credentials.Key.KeyId);
        Assert.Equal("ECDH-ES+A256KW", credentials.Alg);
    }

    [Fact]
    public async Task Jarm_query_mode_returns_one_signed_response_parameter()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);

        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        const string state = "jarm-state";
        var uri = QueryHelpers.AddQueryString("/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["response_mode"] = "query.jwt",
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["scope"] = "openid " + TestDataSeeder.ScopeName,
                ["state"] = state,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Single(query);
        var encoded = query["response"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(encoded));

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);
        Assert.Equal("oauth-authz-resp+jwt", jwt.Typ);
        Assert.Equal("https://sts.tests.local/", jwt.Issuer);
        Assert.Equal(TestDataSeeder.AuthorizationCodeClientId, jwt.Audiences.Single());
        Assert.Equal(state, jwt.GetClaim("state").Value);
        Assert.False(string.IsNullOrWhiteSpace(jwt.GetClaim("code").Value));
        Assert.True(jwt.ValidTo > DateTime.UtcNow);

        var jwksJson = await client.GetStringAsync(
            "/.well-known/openid-configuration/jwks");
        var jwks = new JsonWebKeySet(jwksJson);
        Assert.Contains(jwks.Keys, key => key.Kid == jwt.Kid);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = TestDataSeeder.AuthorizationCodeClientId,
                IssuerSigningKeys = jwks.Keys,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });
        Assert.True(validation.IsValid, validation.Exception?.Message);
    }

    [Fact]
    public async Task Jarm_signs_authorization_error_responses_too()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var uri = QueryHelpers.AddQueryString("/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["response_mode"] = "query.jwt",
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["scope"] = "openid",
                ["state"] = "error-state",
                ["prompt"] = "none",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var parameters = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Single(parameters);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(
            parameters["response"].ToString());
        Assert.Equal("login_required", jwt.GetClaim("error").Value);
        Assert.Equal("error-state", jwt.GetClaim("state").Value);
        Assert.False(jwt.TryGetPayloadValue("code", out string _));
    }
}
