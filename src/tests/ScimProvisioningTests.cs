using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Scim;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ScimProvisioningTests
{
    [Fact]
    public async Task Discovery_exposes_supported_SCIM_contract()
    {
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);
        var client = factory.CreateClient();

        using var config = await client.GetAsync(
            "/scim/v2/service-provider-config");
        var json = await config.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, config.StatusCode);
        Assert.Equal(
            "application/scim+json",
            config.Content.Headers.ContentType?.MediaType);
        Assert.Contains(ScimSchemas.ServiceProviderConfig, json);
        Assert.Contains("\"patch\":{\"supported\":true}", json);
        Assert.Contains("\"bulk\":{\"supported\":false", json);
        Assert.Contains("\"filter\":{\"supported\":true", json);

        using var resources = await client.GetAsync(
            "/scim/v2/resource-types");
        using var schemas = await client.GetAsync("/scim/v2/schemas");
        Assert.Equal(HttpStatusCode.OK, resources.StatusCode);
        Assert.Equal(HttpStatusCode.OK, schemas.StatusCode);
        Assert.Contains(
            ScimSchemas.User,
            await schemas.Content.ReadAsStringAsync());
        Assert.Contains(
            ScimSchemas.Group,
            await schemas.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Users_support_create_filter_patch_and_safe_delete()
    {
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);
        var client = factory.CreateClient();
        var userName = $"scim-{Guid.NewGuid():N}";
        const string password = "Scim!Provisioning#42";

        using var createdResponse = await client.PostAsync(
            "/scim/v2/users",
            ScimJson(new
            {
                schemas = new[] { ScimSchemas.User },
                externalId = $"external-{userName}",
                userName,
                displayName = "SCIM Test User",
                name = new
                {
                    givenName = "SCIM",
                    familyName = "Test"
                },
                active = true,
                emails = new[]
                {
                    new
                    {
                        value = $"{userName}@tests.local",
                        type = "work",
                        primary = true
                    }
                },
                password
            }));
        var createdJson = await createdResponse.Content.ReadAsStringAsync();
        var created = await createdResponse.Content
            .ReadFromJsonAsync<ScimUserResource>();

        Assert.Equal(HttpStatusCode.Created, createdResponse.StatusCode);
        Assert.Equal(
            "application/scim+json",
            createdResponse.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(created);
        Assert.NotNull(created.Id);
        Assert.Equal(userName, created.UserName);
        Assert.DoesNotContain(password, createdJson, StringComparison.Ordinal);
        Assert.Equal(
            created.Meta?.Location,
            createdResponse.Headers.Location?.ToString());

        using var filteredResponse = await client.GetAsync(
            $"/scim/v2/users?filter={Uri.EscapeDataString($"userName eq \"{userName}\"")}&startIndex=1&count=10");
        var filtered = await filteredResponse.Content
            .ReadFromJsonAsync<ScimListResponse<ScimUserResource>>();
        var filteredJson = await filteredResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, filteredResponse.StatusCode);
        Assert.NotNull(filtered);
        Assert.Equal(1, filtered.TotalResults);
        Assert.Equal(created.Id, Assert.Single(filtered.Resources).Id);
        Assert.Contains("\"Resources\":", filteredJson);
        Assert.DoesNotContain("\"resources\":", filteredJson);

        using var patchedResponse = await client.PatchAsync(
            $"/scim/v2/users/{created.Id}",
            ScimJson(new
            {
                schemas = new[] { ScimSchemas.PatchOperation },
                operations = new object[]
                {
                    new
                    {
                        op = "replace",
                        path = "active",
                        value = false
                    },
                    new
                    {
                        op = "replace",
                        path = "displayName",
                        value = "Provisioned Inactive User"
                    }
                }
            }));
        var patched = await patchedResponse.Content
            .ReadFromJsonAsync<ScimUserResource>();
        Assert.Equal(HttpStatusCode.OK, patchedResponse.StatusCode);
        Assert.NotNull(patched);
        Assert.False(patched.Active);
        Assert.Equal("Provisioned Inactive User", patched.DisplayName);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider
                .GetRequiredService<AppDbContext>();
            var persisted = await database.Users.AsNoTracking()
                .SingleAsync(user => user.Id == created.Id);
            Assert.True(persisted.LockoutEnd > DateTimeOffset.UtcNow);
            Assert.Contains(
                await database.ManagementAuditEvents
                    .Where(entry => entry.ResourceId == created.Id)
                    .ToArrayAsync(),
                entry =>
                    entry.Capability == "scim.users.write"
                    && entry.ReasonCode == "scim_user_replaced");
        }

        using var deletedResponse = await client.DeleteAsync(
            $"/scim/v2/users/{created.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deletedResponse.StatusCode);

        await using var verification = factory.Services.CreateAsyncScope();
        var verificationDatabase = verification.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.False(await verificationDatabase.Users.AnyAsync(
            user => user.Id == created.Id));
        Assert.False(await verificationDatabase.ScimUserProfiles.AnyAsync(
            profile => profile.UserId == created.Id));
    }

    [Fact]
    public async Task Groups_are_editable_and_never_become_identity_roles()
    {
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);
        var client = factory.CreateClient();

        string userId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"group-member-{Guid.NewGuid():N}",
                "Original!Passw0rd#17");
            userId = user.Id;
            Assert.Empty(await userManager.GetRolesAsync(user));
        }

        using var createdResponse = await client.PostAsync(
            "/scim/v2/groups",
            ScimJson(new
            {
                schemas = new[] { ScimSchemas.Group },
                externalId = $"group-{Guid.NewGuid():N}",
                displayName = "Provisioning Operators",
                members = new[]
                {
                    new
                    {
                        value = userId,
                        type = "User"
                    }
                }
            }));
        var created = await createdResponse.Content
            .ReadFromJsonAsync<ScimGroupResource>();
        Assert.Equal(HttpStatusCode.Created, createdResponse.StatusCode);
        Assert.NotNull(created);
        Assert.Equal(userId, Assert.Single(created.Members).Value);

        using var patchedResponse = await client.PatchAsync(
            $"/scim/v2/groups/{created.Id}",
            ScimJson(new
            {
                schemas = new[] { ScimSchemas.PatchOperation },
                operations = new[]
                {
                    new
                    {
                        op = "remove",
                        path = $"members[value eq \"{userId}\"]"
                    }
                }
            }));
        var patched = await patchedResponse.Content
            .ReadFromJsonAsync<ScimGroupResource>();
        Assert.Equal(HttpStatusCode.OK, patchedResponse.StatusCode);
        Assert.NotNull(patched);
        Assert.Empty(patched.Members);

        await using var verification = factory.Services.CreateAsyncScope();
        var userManagerVerification = verification.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManagerVerification.FindByIdAsync(userId);
        Assert.NotNull(persisted);
        Assert.Empty(await userManagerVerification.GetRolesAsync(persisted));
        Assert.True(await verification.ServiceProvider
            .GetRequiredService<AppDbContext>()
            .ScimGroups.AnyAsync(group => group.Id == created.Id));
    }

    [Fact]
    public async Task Invalid_filter_returns_SCIM_error_document()
    {
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);

        using var response = await factory.CreateClient().GetAsync(
            "/scim/v2/users?filter=emails.value%20co%20%22example.com%22");
        var error = await response.Content.ReadFromJsonAsync<ScimError>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            "application/scim+json",
            response.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(error);
        Assert.Equal("400", error.Status);
        Assert.Equal("invalidFilter", error.ScimType);
        Assert.Contains(ScimSchemas.Error, error.Schemas);
    }

    [Fact]
    public async Task Authorization_is_required_by_default()
    {
        using var parent = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: true);

        using var response = await factory.CreateClient().GetAsync(
            "/scim/v2/service-provider-config");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            challenge => string.Equals(
                challenge.Scheme,
                "Bearer",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Disabling_scope_authorization_does_not_make_scim_anonymous()
    {
        using var parent = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);

        using var response = await factory.CreateClient().GetAsync(
            "/scim/v2/service-provider-config");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Denied_SCIM_requests_are_written_by_the_authorization_middleware()
    {
        using var parent = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: true);

        using var response = await factory.CreateClient().GetAsync(
            "/scim/v2/users");
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .OrderByDescending(item => item.Id)
            .FirstOrDefaultAsync(item => item.Capability == "scim.authorization");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotNull(audit);
        Assert.Equal("denied", audit.AuthorizationOutcome);
        Assert.Equal("not_authenticated", audit.ReasonCode);
        Assert.Equal("/scim/v2/users", audit.ResourceId);
    }

    /// <summary>
    /// Regression (eval 2026-08-23, S-5): a SCIM read used to persist its
    /// audit row and call SaveChanges inline, so every GET became a write and
    /// a polling client could amplify a read-only workload into sustained
    /// write load. The row is now queued and written by a background worker —
    /// the trail must still arrive, just not on the request path.
    /// </summary>
    [Fact]
    public async Task Read_audit_is_written_off_the_request_path()
    {
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, requireAuthorization: false);

        // Capturado ANTES da requisição: o sinal é o PRÓXIMO lote gravado, e
        // ler depois do GET poderia perder o lote que já passou.
        //
        // A versão anterior sondava a tabela por até 10 segundos de relógio.
        // Isso passava com a máquina ociosa e falhava com ela carregada, e a
        // falha ("audit era nulo") acusava a auditoria de não gravar quando o
        // que faltou foi tempo. Esperar o evento termina assim que o worker
        // grava; o limite abaixo existe só para não travar a suíte se ele
        // morrer.
        var queue = factory.Services.GetRequiredService<ScimAuditQueue>();
        var flushed = queue.Flushed;

        using var response = await factory.CreateClient().GetAsync("/scim/v2/users");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Esta é a única leitura SCIM do teste, então o próximo lote é o dela.
        await flushed.WaitAsync(TimeSpan.FromSeconds(30));

        // A contabilidade tem de refletir a tabela, senão o aviso de rastro
        // incompleto no desligamento mente nas duas direções.
        Assert.Equal(0, queue.Backlog);
        Assert.Equal(0, queue.Dropped);
        Assert.True(queue.Persisted >= 1);

        ManagementAuditEvent? audit;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            audit = await database.ManagementAuditEvents
                .OrderByDescending(item => item.Id)
                .FirstOrDefaultAsync(item => item.ReasonCode == "scim_users_listed");
        }

        Assert.NotNull(audit);
        Assert.Equal("scim.users.read", audit.Capability);
        Assert.Equal("scim-user-collection", audit.ResourceType);
        Assert.Equal("allowed", audit.AuthorizationOutcome);
    }

    /// <summary>
    /// Regression (eval 2026-08-23, S-7): SCIM is a machine-to-machine
    /// surface, but RequireMfa (true by default) can never be satisfied by a
    /// client-credentials token — it authenticates an application, so it has
    /// no <c>sub</c> and never carries <c>amr</c>. Every denial used to be
    /// audited as "scope_denied", sending operators to re-grant a scope the
    /// token already held. The audit must name the real cause.
    /// </summary>
    [Fact]
    public async Task Mfa_denial_of_a_client_credentials_token_is_diagnosed()
    {
        using var parent = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)parent).InitializeAsync();
        // RequireMfa=true is the production default, and it is exactly what
        // makes the M2M caller unauthorizable. RequiredScope is a scope the
        // seeded client-credentials caller can actually request, so the token
        // carries what the policy asks for and MFA is the only unmet
        // requirement.
        using var factory = ScimFactory(
            parent,
            requireAuthorization: true,
            requireMfa: true,
            requiredScope: TestDataSeeder.ScopeName);

        using var client = factory.CreateClient();
        using var token = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            }));
        token.EnsureSuccessStatusCode();
        var accessToken = (await token.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("access_token").GetString();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer", accessToken);

        using var response = await client.GetAsync("/scim/v2/users");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .OrderByDescending(item => item.Id)
            .FirstOrDefaultAsync(item => item.Capability == "scim.authorization");

        Assert.NotNull(audit);
        // Not "scope_denied": the token carries "scim".
        Assert.Equal(
            "mfa_required_unsatisfiable_for_client_credentials",
            audit.ReasonCode);
    }

    private static WebApplicationFactory<ManagementTestFactory> ScimFactory(
        ManagementTestFactory parent,
        bool requireAuthorization,
        bool requireMfa = false,
        string requiredScope = "scim") =>
        parent.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["Sufficit:Identity:Scim:Enabled"] = "true",
                        ["Sufficit:Identity:Scim:RequireAuthorization"] =
                            requireAuthorization.ToString(),
                        ["Sufficit:Identity:Scim:RequireAllowedClient"] = "false",
                        // These tests exercise the SCIM contract without
                        // minting a delegated MFA token. Production defaults
                        // remain RequireMfa=true.
                        ["Sufficit:Identity:Scim:RequireMfa"] =
                            requireMfa.ToString(),
                        ["Sufficit:Identity:Scim:RequiredScope"] = requiredScope
                    });
            });
            builder.ConfigureServices((context, services) =>
                services.AddSufficitIdentityScim(context.Configuration));
        });

    private static StringContent ScimJson(object value) =>
        new(
            JsonSerializer.Serialize(
                value,
                new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                }),
            Encoding.UTF8,
            "application/scim+json");
}
