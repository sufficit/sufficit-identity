using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    [Fact]
    public async Task User_vault_management_lists_metadata_and_cleans_only_the_target_user()
    {
        var options = new VaultOptions { Enabled = true };
        var (vault, dbFactory) = CreateRealVault(options);
        var named = new VaultBackedSecretStore(
            dbFactory,
            vault,
            options);
        var personal = new UserVaultPersonalSecretService(named, options);

        await personal.PutAsync(
            "11111111-1111-1111-1111-111111111111",
            "personal",
            "providers/manual/api-key",
            new SaveUserVaultSecret("alice-personal"));
        await named.PutAsync(
            "integrations/oauth/tokens/github",
            "alice-github",
            "11111111-1111-1111-1111-111111111111",
            "user-11111111-1111-1111-1111-111111111111");
        await named.PutAsync(
            "integrations/oauth/pending/state",
            "transient-state",
            "11111111-1111-1111-1111-111111111111",
            "user-11111111-1111-1111-1111-111111111111");
        await personal.PutAsync(
            "22222222-2222-2222-2222-222222222222",
            "personal",
            "providers/manual/api-key",
            new SaveUserVaultSecret("bob-personal"));

        await using var database = await dbFactory.CreateDbContextAsync();
        var service = new UserVaultManagementService(
            database,
            named,
            Options.Create(options),
            new ManagementOperationGuard(
                new AllowingManagementAuthorizationEvaluator(),
                database,
                new MemoryCache(new MemoryCacheOptions()),
                NullLogger<ManagementOperationGuard>.Instance));
        var context = new ManagementRequestContext(
            new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "vault-operator")],
                "test")),
            "vault-user-management-test");

        var page = await service.ListUsersAsync(
            new VaultUserInventoryQuery("11111111-1111-1111-1111-111111111111"),
            context);

        var alice = Assert.Single(page.Items);
        Assert.Equal("11111111-1111-1111-1111-111111111111", alice.OwnerSubject);
        Assert.False(alice.UserExists);
        Assert.Null(alice.Email);
        Assert.Equal(1, alice.PersonalSecretCount);
        Assert.Equal(1, alice.ManagedCredentialCount);
        Assert.Equal(1, page.TotalPersonalSecrets);
        Assert.Equal(1, page.TotalManagedCredentials);

        var detail = Assert.IsType<VaultUserDetail>(
            await service.GetUserAsync("11111111-1111-1111-1111-111111111111", context));
        Assert.Single(detail.PersonalSecrets);
        Assert.Single(detail.ManagedCredentials);
        Assert.Equal("github", detail.ManagedCredentials[0].Provider);
        Assert.DoesNotContain(
            detail.GetType().GetProperties(),
            property => property.Name is "Value" or "Ciphertext" or "AadJson");

        var cleanup = await service.ClearUserAsync("11111111-1111-1111-1111-111111111111", context);
        Assert.Equal(1, cleanup.PersonalSecretsDeleted);
        Assert.Equal(1, cleanup.ManagedCredentialsDeleted);
        Assert.Null(await service.GetUserAsync("missing-user", context));
        Assert.Single(await personal.ListAsync("22222222-2222-2222-2222-222222222222", "personal"));
        Assert.NotNull(await named.ResolveAsync(
            "integrations/oauth/pending/state",
            "user-11111111-1111-1111-1111-111111111111"));

        var audit = await database.ManagementAuditEvents.AsNoTracking()
            .SingleAsync(item => item.ReasonCode == "vault_user_cleared");
        Assert.Equal(ManagementResourceTypes.VaultUser, audit.ResourceType);
        Assert.Equal("11111111-1111-1111-1111-111111111111", audit.ResourceId);
    }

    [Fact]
    public void User_vault_management_contracts_never_expose_secret_values()
    {
        var contracts = new[]
        {
            typeof(VaultUserInventoryPage),
            typeof(VaultUserInventoryItem),
            typeof(VaultUserDetail),
            typeof(VaultUserCleanupResult),
            typeof(UserVaultSecretMetadata),
            typeof(UserVaultManagedCredentialMetadata),
        };

        foreach (var contract in contracts)
        {
            var names = contract.GetProperties()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.DoesNotContain("Value", names);
            Assert.DoesNotContain("Ciphertext", names);
            Assert.DoesNotContain("AadJson", names);
        }
    }
}
