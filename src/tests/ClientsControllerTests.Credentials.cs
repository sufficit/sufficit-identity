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

public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task Rotate_secret_generates_a_one_time_value_and_invalidates_the_previous_credential()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-rotate-{Guid.NewGuid():N}";
        var previousSecret = $"previous-secret-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = previousSecret,
            DisplayName = "Rotating machine client",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            Scopes = [TestDataSeeder.ScopeName],
        };

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(before);
        Assert.True(before.HasClientSecret);

        using var rotated = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/secret/rotate",
            new RotateClientSecretRequest
            {
                ExpectedVersion = before.Version,
                Generate = true,
            });

        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var result = await rotated.Content
            .ReadFromJsonAsync<RotateManagementClientSecretResult>();
        Assert.NotNull(result);
        Assert.True(result.Generated);
        Assert.True(result.Client.HasClientSecret);
        Assert.Equal(ClientTypes.Confidential, result.Client.Type);
        Assert.NotEqual(before.Version, result.Client.Version);
        Assert.InRange(result.OneTimeSecret.Length, 43, 512);
        Assert.DoesNotContain(previousSecret, await rotated.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);

        var (oldStatus, _) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = previousSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        var (newStatus, token) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = result.OneTimeSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });

        Assert.Equal(HttpStatusCode.Unauthorized, oldStatus);
        Assert.Equal(HttpStatusCode.OK, newStatus);
        Assert.False(string.IsNullOrWhiteSpace(
            token.GetProperty("access_token").GetString()));

        using var stale = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/secret/rotate",
            new RotateClientSecretRequest
            {
                ExpectedVersion = before.Version,
                Generate = true,
            });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .SingleAsync(entry => entry.ResourceId == clientId
                && entry.ReasonCode == "client_secret_rotated");
        Assert.Equal("identity.clients.update", audit.Capability);
        Assert.Equal("succeeded", audit.OperationOutcome);
        Assert.DoesNotContain(result.OneTimeSecret, audit.CorrelationId,
            StringComparison.Ordinal);
        Assert.DoesNotContain(result.OneTimeSecret, audit.OperatorSubject,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rotate_secret_accepts_a_valid_custom_value_and_makes_a_public_client_confidential()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"public-to-confidential-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            DisplayName = "Public client",
            GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
            RedirectUris = ["https://client.tests.local/callback"],
        };

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(before);
        Assert.False(before.HasClientSecret);
        Assert.Equal(ClientTypes.Public, before.Type);

        using var invalid = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/secret/rotate",
            new RotateClientSecretRequest
            {
                ExpectedVersion = before.Version,
                Generate = false,
                ClientSecret = "too-short",
            });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Contains("entre 32 e 512", await invalid.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);

        var replacement = $"custom-replacement-{Guid.NewGuid():N}";
        using var rotated = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/secret/rotate",
            new RotateClientSecretRequest
            {
                ExpectedVersion = before.Version,
                Generate = false,
                ClientSecret = replacement,
            });

        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var result = await rotated.Content
            .ReadFromJsonAsync<RotateManagementClientSecretResult>();
        Assert.NotNull(result);
        Assert.False(result.Generated);
        Assert.Equal(replacement, result.OneTimeSecret);
        Assert.True(result.Client.HasClientSecret);
        Assert.Equal(ClientTypes.Confidential, result.Client.Type);

        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        Assert.True(await applications.ValidateClientSecretAsync(
            application,
            replacement));
    }

    [Fact]
    public async Task Additional_credentials_overlap_then_revoke_without_downtime()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-multiple-{Guid.NewGuid():N}";
        var primarySecret = $"primary-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = primarySecret,
            DisplayName = "Multiple credential client",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            Scopes = [TestDataSeeder.ScopeName],
        };

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        var createdBody = await created.Content.ReadAsStringAsync();
        Assert.True(created.StatusCode == HttpStatusCode.Created, createdBody);
        var detail = JsonSerializer.Deserialize<ManagementClientDetail>(
            createdBody,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(detail);

        using var added = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials",
            new CreateClientCredentialRequest
            {
                ExpectedClientVersion = detail.Version,
                Label = "production rollover",
                Generate = true,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(30),
            });
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        var addition = await added.Content
            .ReadFromJsonAsync<CreateManagementClientCredentialResult>();
        Assert.NotNull(addition);
        Assert.False(addition.CreatedAsPrimary);
        Assert.True(addition.Generated);
        Assert.InRange(addition.OneTimeSecret.Length, 43, 512);
        Assert.Equal(2, addition.Overview.Credentials.Count);
        Assert.Contains("client_secret_basic", addition.Overview.AuthenticationMethods);

        using var listed = await client.GetAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials");
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        var listedJson = await listed.Content.ReadAsStringAsync();
        Assert.DoesNotContain(addition.OneTimeSecret, listedJson, StringComparison.Ordinal);
        var overview = JsonSerializer.Deserialize<ManagementClientCredentialsOverview>(
            listedJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(overview);
        var additional = Assert.Single(
            overview.Credentials,
            credential => !credential.IsPrimary);
        // The hint is a non-reversible fingerprint of the stored hash, so it
        // must NOT carry any slice of the plaintext secret (eval 2026-08-23,
        // S-3). It still has to be present so operators can tell credentials
        // apart in the management UI.
        Assert.NotEmpty(additional.SecretHint);
        Assert.DoesNotContain(additional.SecretHint, addition.OneTimeSecret,
            StringComparison.Ordinal);

        var primaryToken = await RequestClientCredentialsTokenAsync(
            client,
            clientId,
            primarySecret);
        var overlappingToken = await RequestClientCredentialsTokenAsync(
            client,
            clientId,
            addition.OneTimeSecret);
        Assert.Equal(HttpStatusCode.OK, primaryToken);
        Assert.Equal(HttpStatusCode.OK, overlappingToken);

        using var revoked = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials/{additional.Id}/revoke",
            new RevokeClientCredentialRequest
            {
                ExpectedCredentialVersion = additional.Version,
                Reason = "rollover completed",
            });
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var afterRevocation = await revoked.Content
            .ReadFromJsonAsync<ManagementClientCredentialsOverview>();
        Assert.Equal("revoked", afterRevocation!.Credentials.Single(
            credential => credential.Id == additional.Id).Status);

        using var staleRevocation = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials/{additional.Id}/revoke",
            new RevokeClientCredentialRequest
            {
                ExpectedCredentialVersion = additional.Version,
            });
        Assert.Equal(HttpStatusCode.Conflict, staleRevocation.StatusCode);

        Assert.Equal(HttpStatusCode.OK, await RequestClientCredentialsTokenAsync(
            client,
            clientId,
            primarySecret));
        Assert.Equal(HttpStatusCode.Unauthorized,
            await RequestClientCredentialsTokenAsync(
                client,
                clientId,
                addition.OneTimeSecret));

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var persisted = await database.OAuthClientCredentials
            .SingleAsync(credential => credential.Id == additional.Id);
        Assert.NotEqual(addition.OneTimeSecret, persisted.SecretHash);
        Assert.DoesNotContain(addition.OneTimeSecret, persisted.SecretHash,
            StringComparison.Ordinal);
        var auditReasons = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == clientId)
            .Select(entry => entry.ReasonCode)
            .ToArrayAsync();
        Assert.Contains("client_credential_created", auditReasons);
        Assert.Contains("client_credential_revoked", auditReasons);
    }

    [Fact]
    public async Task Mtls_certificate_authenticates_binds_and_revokes_the_client()
    {
        using var factory = new ManagementTestFactory(
            extraConfiguration: new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mtls:Enabled"] = "true",
                ["Sufficit:Identity:Mtls:DeploymentMode"] = "DirectTls",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://sts.tests.local"),
        });
        const string clientId = "mtls-management-e2e";
        using var certificate = CreateMtlsClientCertificate(clientId);

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            new CreateClientRequest
            {
                ClientId = clientId,
                ClientSecret = $"bootstrap-{Guid.NewGuid():N}",
                DisplayName = "mTLS management integration",
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
                Scopes = [TestDataSeeder.ScopeName],
            });
        var createdJson = await created.Content.ReadAsStringAsync();
        Assert.True(created.StatusCode == HttpStatusCode.Created, createdJson);
        var detail = JsonSerializer.Deserialize<ManagementClientDetail>(
            createdJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(detail);

        using var registered = await client.PostAsJsonAsync(
            $"/api/clients/{clientId}/certificates",
            new RegisterClientTlsCertificateRequest
            {
                ExpectedClientVersion = detail.Version!,
                KeyId = "production-2026",
                AuthenticationMethod =
                    ClientAuthenticationMethods.SelfSignedTlsClientAuth,
                CertificatePem = certificate.ExportCertificatePem(),
            });
        var registeredJson = await registered.Content.ReadAsStringAsync();
        Assert.True(
            registered.StatusCode == HttpStatusCode.Created,
            registeredJson);
        var overview = JsonSerializer
            .Deserialize<ManagementClientCredentialsOverview>(
                registeredJson,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(overview);
        var binding = Assert.Single(overview.TlsCertificates!);
        Assert.Equal("production-2026", binding.KeyId);
        Assert.Equal(
            ClientAuthenticationMethods.SelfSignedTlsClientAuth,
            binding.AuthenticationMethod);
        Assert.Contains(
            ClientAuthenticationMethods.SelfSignedTlsClientAuth,
            overview.AuthenticationMethods);
        Assert.True(overview.MtlsRuntimeEnabled);
        Assert.False(overview.PkiAuthenticationEnabled);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            Assert.NotNull(application);
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application);
            descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
            await applications.UpdateAsync(application, descriptor);
        }

        using var tokenRequest = CreateMtlsRequest(
            HttpMethod.Post,
            "/connect/token/mtls",
            certificate,
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = clientId,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        using var tokenResponse = await client.SendAsync(tokenRequest);
        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        Assert.True(tokenResponse.StatusCode == HttpStatusCode.OK, tokenJson);
        using var tokenDocument = JsonDocument.Parse(tokenJson);
        var accessToken = tokenDocument.RootElement
            .GetProperty("access_token")
            .GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        using var introspectionRequest = CreateMtlsRequest(
            HttpMethod.Post,
            "/connect/introspect/mtls",
            certificate,
            new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["token"] = accessToken!,
            });
        using var introspectionResponse = await client.SendAsync(
            introspectionRequest);
        var introspectionJson = await introspectionResponse.Content
            .ReadAsStringAsync();
        Assert.True(
            introspectionResponse.StatusCode == HttpStatusCode.OK,
            introspectionJson);
        using var introspectionDocument = JsonDocument.Parse(introspectionJson);
        Assert.True(introspectionDocument.RootElement
            .GetProperty("active")
            .GetBoolean());
        var confirmation = introspectionDocument.RootElement
            .GetProperty("cnf");
        Assert.Equal(
            Base64UrlEncoder.Encode(SHA256.HashData(certificate.RawData)),
            confirmation.GetProperty("x5t#S256").GetString());

        using var refreshed = await client.GetAsync(
            $"/api/clients/{clientId}/credentials");
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var refreshedOverview = await refreshed.Content
            .ReadFromJsonAsync<ManagementClientCredentialsOverview>();
        Assert.NotNull(refreshedOverview);

        using var revoked = await client.PostAsJsonAsync(
            $"/api/clients/{clientId}/certificates/production-2026/revoke",
            new RevokeClientTlsCertificateRequest
            {
                ExpectedClientVersion = refreshedOverview.ClientVersion!,
            });
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var afterRevocation = await revoked.Content
            .ReadFromJsonAsync<ManagementClientCredentialsOverview>();
        Assert.Empty(afterRevocation!.TlsCertificates!);

        using var rejectedRequest = CreateMtlsRequest(
            HttpMethod.Post,
            "/connect/token/mtls",
            certificate,
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = clientId,
            });
        using var rejectedResponse = await client.SendAsync(rejectedRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedResponse.StatusCode);

        await using var auditScope = factory.Services.CreateAsyncScope();
        var database = auditScope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var reasons = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == clientId)
            .Select(entry => entry.ReasonCode)
            .ToArrayAsync();
        Assert.Contains("client_mtls_certificate_registered", reasons);
        Assert.Contains("client_mtls_certificate_revoked", reasons);
    }

    [Fact]
    public async Task Mtls_registration_rejects_private_key_material_without_echoing_it()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"mtls-private-{Guid.NewGuid():N}";
        using var certificate = CreateMtlsClientCertificate(clientId);
        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            ConfidentialClient(
                clientId,
                "https://client.tests.local/callback"));
        var detail = await created.Content
            .ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(detail);
        using var privateKey = certificate.GetRSAPrivateKey();
        Assert.NotNull(privateKey);
        var privatePem = privateKey.ExportPkcs8PrivateKeyPem();

        using var response = await client.PostAsJsonAsync(
            $"/api/clients/{clientId}/certificates",
            new RegisterClientTlsCertificateRequest
            {
                ExpectedClientVersion = detail.Version!,
                AuthenticationMethod =
                    ClientAuthenticationMethods.SelfSignedTlsClientAuth,
                CertificatePem = certificate.ExportCertificatePem()
                    + privatePem,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("chave privada", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(privatePem, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task First_managed_credential_promotes_a_public_client_to_confidential()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"public-managed-credential-{Guid.NewGuid():N}";
        using var created = await client.PostAsJsonAsync("/api/clients",
            new CreateClientRequest
            {
                ClientId = clientId,
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                RedirectUris = ["https://client.tests.local/callback"],
            });
        var before = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(before);
        Assert.Equal(ClientTypes.Public, before.Type);

        using var added = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials",
            new CreateClientCredentialRequest
            {
                ExpectedClientVersion = before.Version,
                Label = "first credential",
                Generate = true,
            });
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        var result = await added.Content
            .ReadFromJsonAsync<CreateManagementClientCredentialResult>();
        Assert.NotNull(result);
        Assert.True(result.CreatedAsPrimary);
        Assert.Single(result.Overview.Credentials);
        Assert.True(result.Overview.Credentials[0].IsPrimary);

        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        Assert.Equal(ClientTypes.Confidential,
            await applications.GetClientTypeAsync(application));
        Assert.True(await applications.ValidateClientSecretAsync(
            application,
            result.OneTimeSecret));
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.False(await database.OAuthClientCredentials
            .AnyAsync(credential => credential.ClientId == clientId));
    }

    [Fact]
    public async Task Additional_credential_honors_not_before_and_expiration()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-window-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = $"primary-{Guid.NewGuid():N}",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            Scopes = [TestDataSeeder.ScopeName],
        };
        using var created = await client.PostAsJsonAsync("/api/clients", request);
        var detail = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(detail);

        using var added = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials",
            new CreateClientCredentialRequest
            {
                ExpectedClientVersion = detail.Version,
                Label = "scheduled",
                Generate = true,
                NotBeforeUtc = DateTimeOffset.UtcNow.AddHours(1),
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(1),
            });
        var addition = await added.Content
            .ReadFromJsonAsync<CreateManagementClientCredentialResult>();
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        Assert.NotNull(addition);
        Assert.Contains(addition.Overview.Credentials,
            credential => credential.Status == "scheduled");
        Assert.Equal(HttpStatusCode.Unauthorized,
            await RequestClientCredentialsTokenAsync(
                client,
                clientId,
                addition.OneTimeSecret));

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var credential = await database.OAuthClientCredentials
                .SingleAsync(candidate => candidate.ClientId == clientId);
            credential.NotBeforeUtc = DateTime.UtcNow.AddMinutes(-1);
            await database.SaveChangesAsync();
        }
        Assert.Equal(HttpStatusCode.OK,
            await RequestClientCredentialsTokenAsync(
                client,
                clientId,
                addition.OneTimeSecret));

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var credential = await database.OAuthClientCredentials
                .SingleAsync(candidate => candidate.ClientId == clientId);
            credential.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
            await database.SaveChangesAsync();
        }
        Assert.Equal(HttpStatusCode.Unauthorized,
            await RequestClientCredentialsTokenAsync(
                client,
                clientId,
                addition.OneTimeSecret));
    }

    [Fact]
    public async Task Additional_credentials_are_bounded_to_limit_hashing_work()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-bounded-{Guid.NewGuid():N}";
        using var created = await client.PostAsJsonAsync("/api/clients",
            new CreateClientRequest
            {
                ClientId = clientId,
                ClientSecret = $"primary-{Guid.NewGuid():N}",
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            });
        var detail = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(detail);

        for (var index = 1; index <= 5; index++)
        {
            using var added = await client.PostAsJsonAsync(
                $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials",
                new CreateClientCredentialRequest
                {
                    ExpectedClientVersion = detail.Version,
                    Label = $"instance-{index}",
                    Generate = true,
                });
            Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        }

        using var rejected = await client.PostAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials",
            new CreateClientCredentialRequest
            {
                ExpectedClientVersion = detail.Version,
                Label = "instance-6",
                Generate = true,
            });
        Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        Assert.Contains("até 5", await rejected.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);

        using var listed = await client.GetAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}/credentials");
        var overview = await listed.Content
            .ReadFromJsonAsync<ManagementClientCredentialsOverview>();
        Assert.NotNull(overview);
        Assert.Equal(5, overview.MaximumActiveAdditionalSharedSecrets);
        Assert.Equal(6, overview.Credentials.Count);
    }

    [Fact]
    public async Task Embedded_public_jwks_enables_private_key_jwt_and_rejects_mixed_authentication()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingKey = new ECDsaSecurityKey(key)
        {
            KeyId = Guid.NewGuid().ToString("N"),
        };
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(signingKey);
        publicJwk.D = null;
        publicJwk.Use = JsonWebKeyUseNames.Sig;
        publicJwk.Alg = SecurityAlgorithms.EcdsaSha256;
        using var secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var secondSigningKey = new ECDsaSecurityKey(secondKey)
        {
            KeyId = Guid.NewGuid().ToString("N"),
        };
        var secondPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            secondSigningKey);
        secondPublicJwk.D = null;
        secondPublicJwk.Use = JsonWebKeyUseNames.Sig;
        secondPublicJwk.Alg = SecurityAlgorithms.EcdsaSha256;
        var jwksJson = JsonSerializer.Serialize(
            new
            {
                keys = new[]
                {
                    new
                    {
                        publicJwk.Kty,
                        publicJwk.Kid,
                        publicJwk.Use,
                        publicJwk.Alg,
                        publicJwk.Crv,
                        publicJwk.X,
                        publicJwk.Y,
                    },
                    new
                    {
                        secondPublicJwk.Kty,
                        secondPublicJwk.Kid,
                        secondPublicJwk.Use,
                        secondPublicJwk.Alg,
                        secondPublicJwk.Crv,
                        secondPublicJwk.X,
                        secondPublicJwk.Y,
                    },
                },
            },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-private-jwt-{Guid.NewGuid():N}";
        using var created = await client.PostAsJsonAsync("/api/clients",
            new CreateClientRequest
            {
                ClientId = clientId,
                JwksJson = jwksJson,
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
                Scopes = [TestDataSeeder.ScopeName],
            });
        var createdJson = await created.Content.ReadAsStringAsync();
        Assert.True(created.StatusCode == HttpStatusCode.Created, createdJson);
        var detail = JsonSerializer.Deserialize<ManagementClientDetail>(
            createdJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(detail);
        Assert.Equal(ClientTypes.Confidential, detail.Type);
        Assert.Contains("private_key_jwt", detail.AuthenticationMethods!);
        Assert.False(detail.HasClientSecret);

        var assertion = CreateClientAssertion(clientId, signingKey);
        var (status, token) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_assertion_type"] = ClientAssertionTypes.JwtBearer,
                ["client_assertion"] = assertion,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrWhiteSpace(
            token.GetProperty("access_token").GetString()));

        var (secondStatus, _) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_assertion_type"] = ClientAssertionTypes.JwtBearer,
                ["client_assertion"] = CreateClientAssertion(
                    clientId,
                    secondSigningKey),
            });
        Assert.Equal(HttpStatusCode.OK, secondStatus);

        var (mixedStatus, mixedBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = $"not-used-{Guid.NewGuid():N}",
                ["client_assertion_type"] = ClientAssertionTypes.JwtBearer,
                ["client_assertion"] = CreateClientAssertion(clientId, signingKey),
            });
        Assert.NotEqual(HttpStatusCode.OK, mixedStatus);
        Assert.Equal("invalid_request", mixedBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Embedded_jwks_rejects_private_key_material_without_echoing_it()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        const string privateValue = "never-echo-this-private-value";
        var jwks = $$"""
            {"keys":[{"kty":"EC","kid":"private","use":"sig","crv":"P-256","x":"x","y":"y","d":"{{privateValue}}"}]}
            """;

        using var response = await client.PostAsJsonAsync("/api/clients",
            new CreateClientRequest
            {
                ClientId = $"cc-private-jwk-{Guid.NewGuid():N}",
                JwksJson = jwks,
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(body.Contains(
            "apenas chaves públicas",
            StringComparison.OrdinalIgnoreCase), body);
        Assert.DoesNotContain(privateValue, body, StringComparison.Ordinal);
    }
}
