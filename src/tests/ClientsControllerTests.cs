using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers <c>ClientsController.Create</c> secure-by-default changes (eval M4 /
/// plan item 2.4): the consent type defaults to <c>Explicit</c> when omitted,
/// and <c>redirect_uri</c> entries are validated (https required except for
/// loopback; fragments rejected). Uses <see cref="ManagementTestFactory"/>,
/// which wires the management module with authorization disabled (item 5.2 —
/// MFA/authz — is a later wave).
/// </summary>
public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task List_supports_server_paging_and_composable_filters()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        foreach (var suffix in new[] { "one", "two", "three" })
        {
            var request = ConfidentialClient(
                $"paged-{suffix}-{Guid.NewGuid():N}",
                "https://client.tests.local/callback");
            request.DisplayName = $"Paginated alpha {suffix}";
            request.GrantTypes = [Permissions.GrantTypes.AuthorizationCode];
            request.Scopes = ["openid"];
            using var created = await client.PostAsJsonAsync("/api/clients", request);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        using var response = await client.GetAsync(
            "/api/clients?q=alpha&type=confidential&grant=authorization_code&page=2&pageSize=1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<ManagementClientPage>();
        Assert.NotNull(page);
        Assert.Equal(3, page.TotalCount);
        Assert.Equal(2, page.Page);
        Assert.Equal(1, page.PageSize);
        Assert.Single(page.Items);
        Assert.Contains("alpha", page.Items[0].DisplayName,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task List_rejects_an_unbounded_page_size()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/clients?pageSize=101");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("pageSize", await response.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task List_returns_an_empty_page_for_a_reproducible_filter_deep_link()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/clients?q=does-not-exist&type=confidential&grant=device_code"
            + "&origin=manifest&status=active&page=3&pageSize=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<ManagementClientPage>();
        Assert.NotNull(page);
        Assert.Equal(0, page.TotalCount);
        Assert.Empty(page.Items);
        Assert.Equal(3, page.Page);
        Assert.Equal(10, page.PageSize);
    }

    private static CreateClientRequest ConfidentialClient(string clientId, params string[] redirectUris) => new()
    {
        ClientId = clientId,
        ClientSecret = $"secret-{clientId}",
        DisplayName = $"Test client {clientId}",
        GrantTypes = { Permissions.GrantTypes.AuthorizationCode },
        RedirectUris = redirectUris.ToList(),
    };

    [Fact]
    public async Task Client_credentials_client_can_issue_token_and_delete_dependents()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-machine-{Guid.NewGuid():N}";
        var clientSecret = $"secret-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = "Machine client",
            GrantTypes = ["client_credentials"],
            Scopes = [TestDataSeeder.ScopeName]
        };

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            request);
        var createdBody = await created.Content
            .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Contains(
            createdBody.GetProperty("permissions").EnumerateArray(),
            permission => permission.GetString()
                == Permissions.Endpoints.Token);

        var (status, token) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = TestDataSeeder.ScopeName
            });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrWhiteSpace(
            token.GetProperty("access_token").GetString()));

        using var deleted = await client.DeleteAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var verification = factory.Services.CreateAsyncScope();
        var database = verification.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.False(await database.Set<
            OpenIddict.EntityFrameworkCore.Models
                .OpenIddictEntityFrameworkCoreApplication>()
            .AnyAsync(application => application.ClientId == clientId));
    }

    // ----------------------------------------------------------------------
    // Item 3.3 — Pushed Authorization Request (RFC 9126) requirement, opt-in
    // per client. Proves the requirement is persisted when requested and
    // absent when not (so legacy clients are unaffected).
    // ----------------------------------------------------------------------

    // ----------------------------------------------------------------------
    // Eval test-coverage gap: assert that the management authz gate actually
    // rejects requests without the admin scope. Uses a factory variant that
    // does NOT bypass authorization (the real ScopeHandler runs).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Management_endpoints_reject_request_without_admin_scope()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        // No Authorization header → the [Authorize(Policy=...)] gate rejects.
        using var response = await client.GetAsync("/api/clients");
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"Expected 401/403 without admin scope, got {response.StatusCode}.");
        Assert.Null(response.Headers.Location);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            challenge => string.Equals(
                challenge.Scheme,
                "Bearer",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Detail_returns_the_canonical_client_contract()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-detail-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.RequirePar = true;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(clientId, body.GetProperty("clientId").GetString());
        Assert.Contains(
            body.GetProperty("redirectUris").EnumerateArray(),
            value => value.GetString() == "https://client.tests.local/callback");
        Assert.False(body.TryGetProperty("clientSecret", out _));
    }

    [Fact]
    public async Task Update_preserves_secret_and_rejects_stale_version()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-update-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";

        var createRequest = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        createRequest.ClientSecret = secret;
        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            createRequest);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await created.Content.ReadFromJsonAsync<JsonElement>();
        var version = before.GetProperty("version").GetString();

        using var updated = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Updated client",
                ConsentType = "explicit",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                Scopes = ["profile"],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = version,
                AccessTokenLifetimeMinutes = 23,
                IdentityTokenLifetimeMinutes = 11,
                RefreshTokenLifetimeDays = 42,
            });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var after = await updated.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Updated client", after.GetProperty("displayName").GetString());
        Assert.Equal(23, after.GetProperty("accessTokenLifetimeMinutes").GetInt32());
        Assert.Equal(11, after.GetProperty("identityTokenLifetimeMinutes").GetInt32());
        Assert.Equal(42, after.GetProperty("refreshTokenLifetimeDays").GetInt32());
        Assert.False(after.TryGetProperty("clientSecret", out _));

        using var inherited = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Updated client",
                ConsentType = "explicit",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                Scopes = ["profile"],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = after.GetProperty("version").GetString(),
                ClearAccessTokenLifetime = true,
                ClearIdentityTokenLifetime = true,
                ClearRefreshTokenLifetime = true,
            });
        Assert.Equal(HttpStatusCode.OK, inherited.StatusCode);
        var inheritedBody = await inherited.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(inheritedBody.GetProperty("accessTokenLifetimeMinutes").ValueKind is JsonValueKind.Null);
        Assert.True(inheritedBody.GetProperty("identityTokenLifetimeMinutes").ValueKind is JsonValueKind.Null);
        Assert.True(inheritedBody.GetProperty("refreshTokenLifetimeDays").ValueKind is JsonValueKind.Null);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            Assert.NotNull(application);
            Assert.True(await applications.ValidateClientSecretAsync(application, secret));
        }

        using var stale = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Stale update",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = version
            });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
    }

    [Fact]
    public async Task Create_and_delete_append_redacted_audit_events()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.ClientSecret = secret;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var deleted = await client.DeleteAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == clientId)
            .OrderBy(entry => entry.Id)
            .ToArrayAsync();

        Assert.Collection(
            events,
            entry =>
            {
                Assert.Equal("identity.clients.create", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            },
            entry =>
            {
                Assert.Equal("identity.clients.delete", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            });
        Assert.All(events, entry =>
        {
            Assert.DoesNotContain(secret, entry.OperatorSubject, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, entry.CorrelationId, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Audit_endpoint_returns_persisted_mutations()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-list-{Guid.NewGuid():N}";

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            ConfidentialClient(
                clientId,
                "https://client.tests.local/callback"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync("/api/audit?limit=10");
        var records = await response.Content
            .ReadFromJsonAsync<ManagementAuditRecord[]>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            records!,
            entry => entry.ResourceId == clientId
                && entry.Capability == "identity.clients.create");
    }

    private static async Task<HttpStatusCode> RequestClientCredentialsTokenAsync(
        HttpClient client,
        string clientId,
        string clientSecret)
    {
        var (status, _) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        return status;
    }

    private static X509Certificate2 CreateMtlsClientCertificate(string name)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={name}"),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.2"),
                },
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(2));
    }

    private static HttpRequestMessage CreateMtlsRequest(
        HttpMethod method,
        string uri,
        X509Certificate2 certificate,
        IReadOnlyDictionary<string, string> form)
    {
        var request = new HttpRequestMessage(method, uri)
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Headers.Add(
            "X-Sufficit-Test-Client-Certificate",
            Convert.ToBase64String(
                certificate.Export(X509ContentType.Cert)));
        return request;
    }

    private static string CreateClientAssertion(
        string clientId,
        ECDsaSecurityKey key)
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = "https://sts.tests.local/",
            Subject = new ClaimsIdentity([
                new Claim("sub", clientId),
                new Claim("jti", Guid.NewGuid().ToString("N")),
            ]),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(2),
            TokenType = JsonWebTokenTypes.ClientAuthentication,
            SigningCredentials = new SigningCredentials(
                key,
                SecurityAlgorithms.EcdsaSha256),
        });
    }
}
