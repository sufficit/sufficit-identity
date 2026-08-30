using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Vault;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Vault.Crypto;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    [Fact]
    public async Task Named_secret_store_persists_only_ciphertext_and_round_trips()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        var metadata = await store.PutAsync(
            "providers/google/client-secret",
            "super-secret-value",
            "operator-1");

        Assert.Equal("providers/google/client-secret", metadata.Name);
        Assert.Equal("super-secret-value", await store.GetSecretAsync(metadata.Name));
        Assert.Contains(await store.ListAsync(), item => item.Name == metadata.Name);

        await using var database = await dbFactory.CreateDbContextAsync();
        var row = await database.VaultSecrets.SingleAsync(
            item => item.Name == metadata.Name);
        Assert.DoesNotContain("super-secret-value", row.Ciphertext,
            StringComparison.Ordinal);
        Assert.True(await store.DeleteAsync(metadata.Name));
        Assert.Null(await store.GetSecretAsync(metadata.Name));
    }

    [Fact]
    public async Task Named_secret_expiration_blocks_resolution_and_reports_metadata()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        const string name = "providers/asaas/api-token";
        var expiresAtUtc = DateTime.UtcNow.AddDays(3);
        var metadata = await store.PutAsync(
            name, "expiring-value", "operator-1", "global", expiresAtUtc);
        Assert.Equal(expiresAtUtc, metadata.ExpiresAtUtc);

        // Still valid: resolves normally and metadata carries the deadline.
        var resolution = await store.ResolveAsync(name, "global");
        Assert.NotNull(resolution);
        Assert.Equal("expiring-value", resolution.Value);
        Assert.Contains(
            await store.ListAsync(),
            item => item.Name == name && item.ExpiresAtUtc == expiresAtUtc);

        // Force expiry directly in the database (Put refuses past deadlines).
        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var row = await database.VaultSecrets.SingleAsync(
                item => item.Name == name);
            row.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
            await database.SaveChangesAsync();
        }

        // Expired: metadata still visible, plaintext never leaves the vault.
        Assert.Null(await store.GetSecretAsync(name));
        var expired = await store.ResolveAsync(name, "global");
        Assert.NotNull(expired);
        Assert.Null(expired.Value);
        Assert.NotNull(expired.Metadata.ExpiresAtUtc);

        // Absent secrets remain distinguishable from expired ones.
        Assert.Null(await store.ResolveAsync("providers/asaas/other", "global"));
    }

    [Fact]
    public async Task Named_secret_put_rejects_past_expiration()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        await Assert.ThrowsAsync<ArgumentException>(() => store.PutAsync(
            "providers/asaas/api-token",
            "value",
            "operator-1",
            "global",
            DateTime.UtcNow.AddMinutes(-1)));
    }

    [Fact]
    public void Secret_expiration_status_uses_seven_day_warning_window()
    {
        var now = new DateTime(2026, 8, 16, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal(
            Management.Vault.VaultSecretStatus.Active,
            Management.Vault.VaultSecretExpiration.GetStatus(null, now));
        Assert.Equal(
            Management.Vault.VaultSecretStatus.Active,
            Management.Vault.VaultSecretExpiration.GetStatus(now.AddDays(8), now));
        Assert.Equal(
            Management.Vault.VaultSecretStatus.ExpiringSoon,
            Management.Vault.VaultSecretExpiration.GetStatus(now.AddDays(6), now));
        Assert.Equal(
            Management.Vault.VaultSecretStatus.Expired,
            Management.Vault.VaultSecretExpiration.GetStatus(now, now));
    }

    [Fact]
    public async Task Named_secrets_are_isolated_by_context_and_namespace()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        await store.PutAsync(
            "Providers/Google/Client-Secret",
            "tenant-a-secret",
            "operator-a",
            "tenant-a");
        await store.PutAsync(
            "providers/google/client-secret",
            "tenant-b-secret",
            "operator-b",
            "tenant-b");
        await store.PutAsync(
            "billing/gateway/api-key",
            "billing-secret",
            "operator-a",
            "tenant-a");

        Assert.Equal(
            "tenant-a-secret",
            await store.GetSecretAsync(
                "providers/google/client-secret",
                "tenant-a"));
        Assert.Equal(
            "tenant-b-secret",
            await store.GetSecretAsync(
                "providers/google/client-secret",
                "tenant-b"));
        Assert.Null(await store.GetSecretAsync(
            "providers/google/client-secret",
            "tenant-c"));

        var providersOnly = await store.ListAsync(
            "tenant-a",
            new HashSet<string>(["providers"], StringComparer.Ordinal));
        var provider = Assert.Single(providersOnly);
        Assert.Equal("providers", provider.Namespace);
        Assert.Equal("tenant-a", provider.ContextId);
        Assert.Equal("operator-a", provider.OwnerSubject);
        Assert.False(await store.DeleteAsync(
            "providers/google/client-secret",
            "tenant-c"));

        await store.PutAsync(
            "providers/google/client-secret",
            "tenant-a-rotated",
            "operator-c",
            "tenant-a");
        var rotated = Assert.Single(await store.ListAsync(
            "tenant-a",
            new HashSet<string>(["providers"], StringComparer.Ordinal)));
        Assert.Equal("operator-a", rotated.OwnerSubject);
        Assert.Equal("operator-c", rotated.UpdatedBy);
        Assert.Equal(
            "tenant-a-rotated",
            await store.GetSecretAsync(rotated.Name, "tenant-a"));
        Assert.Equal(
            "tenant-b-secret",
            await store.GetSecretAsync(rotated.Name, "tenant-b"));

        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var moved = await database.VaultSecrets.SingleAsync(secret =>
                secret.ContextId == "tenant-b"
                && secret.Name == rotated.Name);
            moved.ContextId = "tenant-c";
            await database.SaveChangesAsync();
        }
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            store.GetSecretAsync(rotated.Name, "tenant-c"));
    }

    [Theory]
    [InlineData(" Providers/Google/Client-Secret ", "providers/google/client-secret")]
    [InlineData("billing/API_KEY", "billing/api_key")]
    public void Named_secret_normalization_is_canonical(
        string input,
        string expected) =>
        Assert.Equal(expected, VaultBackedSecretStore.NormalizeName(input));

    [Fact]
    public async Task Vault_contexts_are_pure_organization_and_break_glass_audits()
    {
        // After the multi-tenant removal (2026-08 decision), vault contexts
        // and namespaces are pure data organization: capability + MFA gate
        // access, every operator sees every context, and break-glass (claim +
        // MFA evidence) remains an unmissable audit marker rather than an
        // access bypass.
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });
        await store.PutAsync(
            "providers/google/client-secret",
            "google-secret",
            "seed",
            "global");
        await store.PutAsync(
            "billing/gateway/api-key",
            "billing-secret",
            "seed",
            "global");

        var managementOptions = Options.Create(
            new Sufficit.Identity.Management.ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions(),
        });
        await using var database = await dbFactory.CreateDbContextAsync();
        var service = new VaultSecretsManagementService(
            database,
            store,
            Options.Create(new VaultOptions { Enabled = true }),
            managementOptions,
            new Sufficit.Identity.Management.Audit.ManagementOperationGuard(
                new AllowingManagementAuthorizationEvaluator(),
                database,
                new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<
                    Sufficit.Identity.Management.Audit.ManagementOperationGuard>.Instance));

        // An operator with NO namespace claims sees every namespace: the
        // contexts are folders, not boundaries.
        var plainContext = new ManagementRequestContext(
            new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "operator-1")],
                "test")),
            "organization-test");
        var visible = await service.ListAsync("global", plainContext);
        Assert.Equal(2, visible.Count);

        // Break-glass (dedicated claim + MFA evidence) marks the audit trail.
        var breakGlassPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "incident-operator"),
                new Claim(
                    "identity_vault_break_glass",
                    "identity.vault.secrets"),
                new Claim("amr", "pwd mfa"),
            ],
            "test"));
        var breakGlassContext = new ManagementRequestContext(
            breakGlassPrincipal,
            "break-glass-test");
        Assert.Equal(2, (await service.ListAsync(
            "global",
            breakGlassContext)).Count);

        var audit = await database.ManagementAuditEvents.AsNoTracking()
            .SingleAsync(item => item.CorrelationId == "break-glass-test");
        Assert.Equal("vault_break_glass", audit.ReasonCode);
        Assert.Equal(
            ManagementResourceTypes.VaultSecretCollection,
            audit.ResourceType);
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("name with spaces")]
    [InlineData("name?query")]
    public void Named_secret_store_rejects_unsafe_names(string name)
    {
        Assert.Throws<ArgumentException>(
            () => VaultBackedSecretStore.NormalizeName(name));
    }

    [Fact]
    public async Task Client_secret_resolver_round_trips_with_pass_through()
    {
        IKeyVault vault = new PassThroughKeyVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        // With pass-through, the reference is the plaintext secret itself
        // (dev/migration convenience). Resolve returns it unchanged.
        const string secret = "my-confidential-client-secret";
        var resolved = await resolver.ResolveAsync(secret);

        Assert.Equal(secret, resolved);
    }

    [Fact]
    public async Task Client_secret_resolver_round_trips_with_real_vault()
    {
        var (vault, _) = CreateRealVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        // Store a secret, then resolve the reference back to the plaintext.
        const string plaintext = "super-secret-client-credential";
        var reference = await resolver.StoreAsync(plaintext);
        var resolved = await resolver.ResolveAsync(reference);

        Assert.Equal(plaintext, resolved);
        // The reference must not contain the plaintext.
        Assert.DoesNotContain(plaintext, reference);
    }

    [Fact]
    public async Task Client_secret_resolver_rejects_plaintext_with_real_vault()
    {
        var (vault, _) = CreateRealVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        await Assert.ThrowsAsync<ClientSecretResolutionException>(
            async () => await resolver.ResolveAsync(
                "raw-client-secret-must-not-fall-back"));
    }
}
