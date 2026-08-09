using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SenderConstraintTests
{
    private const string CertificateHeader =
        "X-Sufficit-Test-Client-Certificate";

    [Fact]
    public async Task Mtls_only_issues_bearer_token_with_only_x5t_confirmation()
    {
        using var certificate = CreateCertificate();
        using var factory = CreateFactory(
            certificate,
            TestDataSeeder.ClientCredentialsClientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        AddCertificate(client, certificate);

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        var accessToken = body.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        client.DefaultRequestHeaders.Authorization =
            IntrospectionTests.BasicAuthFor(
                TestDataSeeder.IntrospectionClientId,
                TestDataSeeder.IntrospectionClientSecret);
        var (introspectionStatus, introspection) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = accessToken! });

        Assert.Equal(HttpStatusCode.OK, introspectionStatus);
        var confirmation = introspection.GetProperty("cnf");
        Assert.True(confirmation.TryGetProperty("x5t#S256", out var thumbprint));
        Assert.False(string.IsNullOrWhiteSpace(thumbprint.GetString()));
        Assert.False(confirmation.TryGetProperty("jkt", out _));
    }

    [Fact]
    public async Task Dpop_and_mtls_combination_is_rejected_for_all_reissuance_grants()
    {
        using var certificate = CreateCertificate();
        using var factory = CreateFactory(
            certificate,
            TestDataSeeder.ClientCredentialsClientId,
            TestDataSeeder.AuthorizationCodeClientId,
            TestDataSeeder.TokenExchangeClientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var clientCredentials = await PostWithBothConstraintsAsync(
            client,
            certificate,
            tokenUrl,
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        AssertConstraintConflict(clientCredentials);

        await TestOnlyEndpoints.SignInAsync(
            client,
            TestDataSeeder.DefaultUsername);
        var (codeVerifier, codeChallenge) = Pkce.CreatePair();
        var authorizationCode = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            codeChallenge,
            "openid offline_access");
        var authorizationCodeResult = await PostWithBothConstraintsAsync(
            client,
            certificate,
            tokenUrl,
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = codeVerifier,
            });
        AssertConstraintConflict(authorizationCodeResult);

        var (refreshVerifier, refreshChallenge) = Pkce.CreatePair();
        var refreshCode = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            refreshChallenge,
            "openid offline_access");
        var (initialProof, bindingKey) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", initialProof);
        var (initialStatus, initialBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = refreshCode,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = refreshVerifier,
            });
        client.DefaultRequestHeaders.Remove("DPoP");
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var refreshToken = initialBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var refreshResult = await PostWithBothConstraintsAsync(
            client,
            certificate,
            tokenUrl,
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken!,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            },
            bindingKey);
        AssertConstraintConflict(refreshResult);

        var (subjectStatus, subjectBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        var subjectToken = subjectBody.GetProperty("access_token").GetString();
        var tokenExchange = await PostWithBothConstraintsAsync(
            client,
            certificate,
            tokenUrl,
            new Dictionary<string, string>
            {
                ["grant_type"] =
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ["subject_token"] = subjectToken!,
                ["subject_token_type"] =
                    "urn:ietf:params:oauth:token-type:access_token",
                ["client_id"] = TestDataSeeder.TokenExchangeClientId,
                ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
            });
        AssertConstraintConflict(tokenExchange);
    }

    [Fact]
    public async Task Refresh_token_cannot_switch_from_dpop_to_mtls()
    {
        using var certificate = CreateCertificate();
        using var factory = CreateFactory(
            certificate,
            TestDataSeeder.AuthorizationCodeClientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        await TestOnlyEndpoints.SignInAsync(
            client,
            TestDataSeeder.DefaultUsername);
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            challenge,
            "openid offline_access");
        var (proof, _) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", proof);
        var (initialStatus, initialBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = verifier,
            });
        client.DefaultRequestHeaders.Remove("DPoP");
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var refreshToken = initialBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        AddCertificate(client, certificate);
        var (refreshStatus, refreshBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken!,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            });

        Assert.Equal(HttpStatusCode.BadRequest, refreshStatus);
        Assert.Equal("invalid_grant", refreshBody.GetProperty("error").GetString());
        Assert.Contains(
            "DPoP proof does not match",
            refreshBody.GetProperty("error_description").GetString(),
            StringComparison.Ordinal);
    }

    private static void AssertConstraintConflict(
        (HttpStatusCode Status, JsonElement Body) response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal(
            "invalid_request",
            response.Body.GetProperty("error").GetString());
        Assert.Equal(
            "A token request cannot combine DPoP and mTLS sender constraints.",
            response.Body.GetProperty("error_description").GetString());
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)>
        PostWithBothConstraintsAsync(
            HttpClient client,
            X509Certificate2 certificate,
            string tokenUrl,
            Dictionary<string, string> form,
            ECDsaSecurityKey? signingKey = null)
    {
        AddCertificate(client, certificate);
        var (proof, _) = BuildDpopProof("POST", tokenUrl, signingKey);
        client.DefaultRequestHeaders.Add("DPoP", proof);
        try
        {
            return await client.PostFormAsync("/connect/token", form);
        }
        finally
        {
            client.DefaultRequestHeaders.Remove("DPoP");
            client.DefaultRequestHeaders.Remove(CertificateHeader);
        }
    }

    private static void AddCertificate(
        HttpClient client,
        X509Certificate2 certificate)
    {
        client.DefaultRequestHeaders.Remove(CertificateHeader);
        client.DefaultRequestHeaders.Add(
            CertificateHeader,
            Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
    }

    private static SufficitIdentityTestFactory CreateFactory(
        X509Certificate2 certificate,
        params string[] clientIds)
    {
        var configuration = new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "false",
            ["Sufficit:Identity:Mtls:Enabled"] = "true",
            ["Sufficit:Identity:Mtls:DeploymentMode"] = "DirectTls",
            ["Sufficit:Identity:Mtls:RequireValidCertificateChain"] = "false",
        };
        var thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        for (var index = 0; index < clientIds.Length; index++)
        {
            configuration[
                $"Sufficit:Identity:Mtls:ClientCertificateThumbprints:{clientIds[index]}:0"] =
                thumbprint;
        }

        return SufficitIdentityTestFactory.CreateIsolated(configuration);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=sender-constraint-tests",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
    }

    private static (string Jwt, ECDsaSecurityKey Key) BuildDpopProof(
        string method,
        string url,
        ECDsaSecurityKey? signingKey = null)
    {
        var key = signingKey ?? new ECDsaSecurityKey(
            ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var jwkJson = JsonSerializer.Serialize(jwk);
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = EpochTime.GetIntDate(DateTime.UtcNow),
                ["exp"] = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(1)),
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(
                key,
                SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = DpopProofValidator.DpopHeaderType,
                ["jwk"] = JsonSerializer.Deserialize<JsonElement>(jwkJson),
            },
        };
        return (new JsonWebTokenHandler().CreateToken(descriptor), key);
    }
}
