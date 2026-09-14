using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Registration;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Clients;

/// <summary>
/// Circuit-safe adapter for dynamic client registration initial access tokens.
/// Token values are returned only to the requesting component and are never
/// logged or retained by this adapter.
/// </summary>
public sealed class ManagementRegistrationTokenDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementRegistrationTokenDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public Task<ManagementDataResult<IReadOnlyList<DcrInitialAccessTokenSummary>>> ListAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.ListAsync(context, cancellationToken),
            "list registration tokens",
            cancellationToken);

    public Task<ManagementDataResult<DcrInitialAccessTokenIssueResult>> IssueAsync(
        IssueDcrInitialAccessTokenCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.IssueAsync(command, context, cancellationToken),
            "issue registration token",
            cancellationToken);

    public Task<ManagementDataResult<bool>> RevokeAsync(
        Guid id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (service, context) =>
            {
                await service.RevokeAsync(id, context, cancellationToken);
                return true;
            },
            "revoke registration token",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IDcrInitialAccessTokenManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IDcrInitialAccessTokenManagementService>();
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id
                    ?? $"management-ui-{Guid.NewGuid():N}");
            return ManagementDataResult<T>.Success(
                await operation(service, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Invalid,
                ManagementErrorText.For(localizer, exception),
                exception.Field);
        }
        catch (ManagementNotFoundException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.NotFound,
                ManagementErrorText.For(localizer, exception));
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
                    : localizer["Common.Access.Forbidden"],
                errorDetails: [
                    localizer[
                        "Clients.RegistrationTokens.TechnicalReason",
                        exception.Decision.ReasonCode]
                ]);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(
                "Registration token operation timed out: {OperationName}.",
                operationName);
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
                "Registration token operation failed: {OperationName}.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                localizer["Common.Unavailable"]);
        }
    }
}
