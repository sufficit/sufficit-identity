using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.UI.Vault.Data;

public sealed record VaultDataResult<T>(bool IsSuccess, T? Value, string? Error)
{
    public static VaultDataResult<T> Success(T value) => new(true, value, null);
    public static VaultDataResult<T> Failure(string message) => new(false, default, message);
}

public sealed class VaultDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<VaultDataSource> logger)
{
    public async Task<VaultDataResult<UserVaultOverview>> LoadPersonalOverviewAsync(
        CancellationToken cancellationToken = default)
    {
        var subject = await SubjectAsync();
        if (subject is null)
            return VaultDataResult<UserVaultOverview>.Failure(
                "Sua sessão não possui uma identidade válida.");
        return await ExecuteAsync<IUserVaultOverviewService, UserVaultOverview>(
            (service, _) => service.GetAsync(subject, cancellationToken),
            "personal Vault overview", cancellationToken);
    }

    public async Task<VaultDataResult<UserVaultSecretMetadata>> PutPersonalAsync(
        string @namespace, string name, string value, CancellationToken cancellationToken = default)
    {
        var subject = await SubjectAsync();
        if (subject is null) return VaultDataResult<UserVaultSecretMetadata>.Failure("Sua sessão não possui uma identidade válida.");
        return await ExecuteAsync<IUserVaultService, UserVaultSecretMetadata>(
            (service, _) => service.PutAsync(subject, @namespace, name,
                new SaveUserVaultSecret(value), cancellationToken),
            "personal Vault update", cancellationToken);
    }

    public async Task<VaultDataResult<bool>> DeletePersonalAsync(
        string @namespace, string name, CancellationToken cancellationToken = default)
    {
        var subject = await SubjectAsync();
        if (subject is null) return VaultDataResult<bool>.Failure("Sua sessão não possui uma identidade válida.");
        return await ExecuteAsync<IUserVaultService, bool>(
            async (service, _) => { await service.DeleteAsync(subject, @namespace, name, cancellationToken); return true; },
            "personal Vault deletion", cancellationToken);
    }

    public Task<VaultDataResult<IReadOnlyList<ManagementVaultSecret>>> ListAdminAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IVaultSecretsManagementService, IReadOnlyList<ManagementVaultSecret>>(
            async (service, context) => await service.ListAsync("global", context, cancellationToken),
            "operator Vault listing", cancellationToken, useManagementContext: true);

    public Task<VaultDataResult<ManagementVaultSecret>> PutAdminAsync(
        string name, string value, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IVaultSecretsManagementService, ManagementVaultSecret>(
            (service, context) => service.PutAsync(name, "global", new SaveManagementVaultSecret(value), context, cancellationToken),
            "operator Vault update", cancellationToken, useManagementContext: true);

    public Task<VaultDataResult<bool>> DeleteAdminAsync(
        string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IVaultSecretsManagementService, bool>(
            async (service, context) => { await service.DeleteAsync(name, "global", context, cancellationToken); return true; },
            "operator Vault deletion", cancellationToken, useManagementContext: true);

    public Task<VaultDataResult<VaultUserInventoryPage>> ListVaultUsersAsync(
        string? search,
        int offset,
        int limit,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IUserVaultManagementService, VaultUserInventoryPage>(
            (service, context) => service.ListUsersAsync(
                new VaultUserInventoryQuery(search, offset, limit),
                context,
                cancellationToken),
            "user Vault inventory",
            cancellationToken,
            useManagementContext: true);

    public Task<VaultDataResult<VaultUserDetail?>> LoadVaultUserAsync(
        string ownerSubject,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IUserVaultManagementService, VaultUserDetail?>(
            (service, context) => service.GetUserAsync(
                ownerSubject,
                context,
                cancellationToken),
            "user Vault detail",
            cancellationToken,
            useManagementContext: true);

    public Task<VaultDataResult<bool>> DeleteVaultUserPersonalAsync(
        string ownerSubject,
        string @namespace,
        string name,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IUserVaultManagementService, bool>(
            async (service, context) =>
            {
                await service.DeletePersonalSecretAsync(
                    ownerSubject,
                    @namespace,
                    name,
                    context,
                    cancellationToken);
                return true;
            },
            "user Vault personal-secret deletion",
            cancellationToken,
            useManagementContext: true);

    public Task<VaultDataResult<bool>> DeleteVaultUserManagedAsync(
        string ownerSubject,
        string name,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IUserVaultManagementService, bool>(
            async (service, context) =>
            {
                await service.DeleteManagedCredentialAsync(
                    ownerSubject,
                    name,
                    context,
                    cancellationToken);
                return true;
            },
            "user Vault managed-credential deletion",
            cancellationToken,
            useManagementContext: true);

    public Task<VaultDataResult<VaultUserCleanupResult>> ClearVaultUserAsync(
        string ownerSubject,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IUserVaultManagementService, VaultUserCleanupResult>(
            (service, context) => service.ClearUserAsync(
                ownerSubject,
                context,
                cancellationToken),
            "user Vault cleanup",
            cancellationToken,
            useManagementContext: true);

    private async Task<VaultDataResult<T>> ExecuteAsync<TService, T>(
        Func<TService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken,
        bool useManagementContext = false)
        where TService : notnull
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<TService>();
            var state = await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(state.User, Guid.NewGuid().ToString("N"));
            return VaultDataResult<T>.Success(await operation(service, context));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return VaultDataResult<T>.Failure("O Vault demorou mais que o esperado. Tente novamente.");
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "{OperationName} failed.", operationName);
            return VaultDataResult<T>.Failure("Não foi possível concluir a operação do Vault.");
        }
    }

    private async Task<string?> SubjectAsync()
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync();
        return state.User.FindFirst("sub")?.Value
            ?? state.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }
}
