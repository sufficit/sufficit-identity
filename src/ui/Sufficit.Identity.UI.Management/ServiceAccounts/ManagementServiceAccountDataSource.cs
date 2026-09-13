using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.ServiceAccounts;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.ServiceAccounts;

/// <summary>
/// Bridge from the service-account page to the management service — the same
/// role that <c>ManagementClientDataSource</c> plays for clients: resolves
/// the service in its own scope, builds the context from the circuit's
/// authentication state, and converts management exceptions into the results
/// the page knows how to display.
/// </summary>
public sealed class ManagementServiceAccountDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementServiceAccountDataSource> logger,
    IStringLocalizer<ManagementResource> localizer)
{
    public Task<ManagementDataResult<ServiceAccountWorkspace>> GetWorkspaceAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (accounts, context) => accounts.GetWorkspaceAsync(context, cancellationToken),
            "Service account listing",
            cancellationToken);

    public Task<ManagementDataResult<ServiceAccountSummary>> SetRolesAsync(
        string clientId,
        IReadOnlyList<string> roles,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (accounts, context) => accounts.SetRolesAsync(
                clientId,
                new SetServiceAccountRolesCommand(roles),
                context,
                cancellationToken),
            "Service account role update",
            cancellationToken);

    public Task<ManagementDataResult<ServiceAccountCreated>> CreateAsync(
        string clientId,
        string? displayName,
        IReadOnlyList<string> roles,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (accounts, context) => accounts.CreateAsync(
                new CreateServiceAccountCommand(clientId, displayName, roles),
                context,
                cancellationToken),
            "Service account creation",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IServiceAccountManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var accounts = scope.ServiceProvider
                .GetRequiredService<IServiceAccountManagementService>();
            var context = await CreateRequestContextAsync();

            return ManagementDataResult<T>.Success(
                await operation(accounts, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Invalid,
                ManagementErrorText.For(localizer, exception),
                exception.Field);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? localizer["Common.Access.StepUpRequired"]
                    : localizer["Common.Access.Forbidden"]);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                localizer["Common.Timeout"]);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                localizer["Common.Unavailable"]);
        }
    }

    private async Task<ManagementRequestContext> CreateRequestContextAsync()
    {
        var authenticationState =
            await authenticationStateProvider.GetAuthenticationStateAsync();
        var correlationId = Activity.Current?.Id
            ?? $"management-ui-{Guid.NewGuid():N}";

        return new ManagementRequestContext(
            authenticationState.User,
            correlationId);
    }
}
