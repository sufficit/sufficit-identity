using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Tokens;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// OpenIddict never deletes token entries: codes are marked redeemed,
/// revocation is a status flip, and reference tokens stay forever. The
/// pruning worker applies <see cref="TokenPruningOptions.RetentionDays"/>
/// through OpenIddict's supported <c>PruneAsync</c> path — these tests pin
/// the two bounds that matter: dead entries older than the threshold
/// disappear, and a valid, unexpired token is never pruned regardless of age.
/// </summary>
public sealed class OpenIddictPruningWorkerTests
{
    private const int RetentionDays = 30;

    // Not a TokenTypeIdentifiers constant: the device-code token type only
    // exists in the server package, and the repo's own precedent
    // (DeviceCodeReplayGuard) references it as this literal.
    private const string DeviceCodeType =
        "urn:openiddict:params:oauth:token-type:device_code";

    [Fact]
    public async Task Prune_removes_dead_entries_but_keeps_valid_unexpired_tokens()
    {
        using var factory = CreateFactory();
        var expired = await SeedTokenAsync(factory,
            createdDaysAgo: 40, DeviceCodeType, Statuses.Redeemed,
            expirationDaysFromNow: -39);
        var revoked = await SeedTokenAsync(factory,
            createdDaysAgo: 40, TokenTypeIdentifiers.AccessToken, Statuses.Revoked,
            expirationDaysFromNow: 1);
        var validOld = await SeedTokenAsync(factory,
            createdDaysAgo: 40, TokenTypeIdentifiers.RefreshToken, Statuses.Valid,
            expirationDaysFromNow: 1);
        var deadRecent = await SeedTokenAsync(factory,
            createdDaysAgo: 1, DeviceCodeType, Statuses.Redeemed,
            expirationDaysFromNow: 1);

        await RunPruneAsync(factory, RetentionDays);

        // Redeemed/expired and revoked entries past the threshold are gone.
        await AssertTokenAbsentAsync(factory, expired);
        await AssertTokenAbsentAsync(factory, revoked);
        // A valid token with future expiration survives even though it was
        // created before the threshold — retention never cuts live sessions.
        await AssertTokenPresentAsync(factory, validOld, Statuses.Valid);
        // Dead-but-recent entries stay until they age past the threshold:
        // revocation history remains auditable for the retention window.
        await AssertTokenPresentAsync(factory, deadRecent, Statuses.Redeemed);
    }

    [Fact]
    public async Task Prune_removes_only_orphaned_adhoc_authorizations()
    {
        using var factory = CreateFactory();
        var orphaned = await SeedAuthorizationAsync(factory,
            createdDaysAgo: 40, AuthorizationTypes.AdHoc, attachLiveToken: false);
        var withLiveToken = await SeedAuthorizationAsync(factory,
            createdDaysAgo: 40, AuthorizationTypes.AdHoc, attachLiveToken: true);
        var permanent = await SeedAuthorizationAsync(factory,
            createdDaysAgo: 40, AuthorizationTypes.Permanent, attachLiveToken: false);

        await RunPruneAsync(factory, RetentionDays);

        await AssertAuthorizationAbsentAsync(factory, orphaned);
        await AssertAuthorizationPresentAsync(factory, withLiveToken);
        await AssertAuthorizationPresentAsync(factory, permanent);
    }

    [Fact]
    public async Task Prune_is_disabled_when_retention_days_is_not_positive()
    {
        using var factory = CreateFactory();
        var expired = await SeedTokenAsync(factory,
            createdDaysAgo: 90, DeviceCodeType, Statuses.Redeemed,
            expirationDaysFromNow: -89);

        await RunPruneAsync(factory, retentionDays: 0);

        // Zero (or negative) is an explicit choice to keep everything.
        await AssertTokenPresentAsync(factory, expired, Statuses.Redeemed);
    }

    private static SufficitIdentityTestFactory CreateFactory() =>
        SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:TokenPruning:RetentionDays"] = RetentionDays.ToString(),
            });

    private static async Task RunPruneAsync(
        SufficitIdentityTestFactory factory,
        int retentionDays)
    {
        await ((IAsyncLifetime)factory).InitializeAsync();
        var worker = new OpenIddictPruningWorker(
            new TokenPruningOptions { RetentionDays = retentionDays },
            factory.Services,
            NullLogger<OpenIddictPruningWorker>.Instance);

        // Executa a passada de poda diretamente, em vez de subir o serviço de
        // fundo e dormir esperando que ele tenha terminado. O laço de
        // agendamento não é o que estes testes verificam — a regra de
        // retenção é.
        await worker.PruneAsync(CancellationToken.None);
    }

    private static async Task<string> SeedTokenAsync(
        SufficitIdentityTestFactory factory,
        int createdDaysAgo,
        string type,
        string status,
        int expirationDaysFromNow)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
        {
            CreationDate = DateTimeOffset.UtcNow.AddDays(-createdDaysAgo),
            ExpirationDate = DateTimeOffset.UtcNow.AddDays(expirationDaysFromNow),
            ReferenceId = $"pruning-test-{Guid.NewGuid():N}",
            Subject = TestSubject(),
            Type = type,
            Status = status,
        });
        return (await tokens.GetIdAsync(token))!;
    }

    private static async Task<string> SeedAuthorizationAsync(
        SufficitIdentityTestFactory factory,
        int createdDaysAgo,
        string type,
        bool attachLiveToken)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var authorization = await authorizations.CreateAsync(
            new OpenIddictAuthorizationDescriptor
            {
                Subject = TestSubject(),
                CreationDate = DateTimeOffset.UtcNow.AddDays(-createdDaysAgo),
                Status = Statuses.Valid,
                Type = type,
                Scopes = { Scopes.OpenId },
            });
        var authorizationId = (await authorizations.GetIdAsync(authorization))!;

        if (attachLiveToken)
        {
            var tokens = scope.ServiceProvider
                .GetRequiredService<IOpenIddictTokenManager>();
            await tokens.CreateAsync(new OpenIddictTokenDescriptor
            {
                AuthorizationId = authorizationId,
                CreationDate = DateTimeOffset.UtcNow.AddDays(-createdDaysAgo),
                ExpirationDate = DateTimeOffset.UtcNow.AddDays(1),
                Subject = TestSubject(),
                Type = TokenTypeIdentifiers.RefreshToken,
                Status = Statuses.Valid,
            });
        }

        return authorizationId;
    }

    private static string TestSubject() => $"pruning-test-{Guid.NewGuid():N}";

    private static async Task AssertTokenAbsentAsync(
        SufficitIdentityTestFactory factory,
        string identifier)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        Assert.Null(await tokens.FindByIdAsync(identifier));
    }

    private static async Task AssertTokenPresentAsync(
        SufficitIdentityTestFactory factory,
        string identifier,
        string expectedStatus)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var token = await tokens.FindByIdAsync(identifier);
        Assert.NotNull(token);
        Assert.Equal(expectedStatus, await tokens.GetStatusAsync(token!));
    }

    private static async Task AssertAuthorizationAbsentAsync(
        SufficitIdentityTestFactory factory,
        string identifier)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        Assert.Null(await authorizations.FindByIdAsync(identifier));
    }

    private static async Task AssertAuthorizationPresentAsync(
        SufficitIdentityTestFactory factory,
        string identifier)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        Assert.NotNull(await authorizations.FindByIdAsync(identifier));
    }
}
