using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.OperatorTokens;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.OperatorTokens;

/// <summary>
/// Circuit-safe adapter for the current operator's short-lived Management
/// tokens. Token values are returned only to the requesting component and are
/// never logged or retained by this adapter.
/// </summary>
public sealed class ManagementOperatorTokenDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementOperatorTokenDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public Task<ManagementDataResult<OperatorTokenWorkspace>> GetAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.GetWorkspaceAsync(
                context,
                cancellationToken),
            localizer["OperatorTokens.Operation.ViewTokens"],
            cancellationToken);

    public Task<ManagementDataResult<OperatorTokenIssueResult>> IssueAsync(
        IssueOperatorTokenCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.IssueAsync(
                command,
                context,
                cancellationToken),
            localizer["OperatorTokens.Operation.IssueToken"],
            cancellationToken);

    public Task<ManagementDataResult<bool>> RevokeAsync(
        string id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (service, context) =>
            {
                await service.RevokeAsync(id, context, cancellationToken);
                return true;
            },
            localizer["OperatorTokens.Operation.RevokeToken"],
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IOperatorTokenManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IOperatorTokenManagementService>();
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
        catch (ManagementConflictException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Conflict,
                ManagementErrorText.For(localizer, exception),
                errorDetails: [
                    localizer["OperatorTokens.Conflict.CheckPolicy"]
                ]);
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
            var message = outcome is ManagementDataOutcome.StepUpRequired
                ? localizer["Common.Access.StepUpRequired"]
                : localizer["Common.Access.Forbidden"];
            return ManagementDataResult<T>.Failure(
                outcome,
                message,
                errorDetails: [
                    localizer[
                        "OperatorTokens.Access.TechnicalReason",
                        exception.Decision.ReasonCode]
                ]);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(
                "Temporary operator-token operation timed out: {OperationName}.",
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
                "Temporary operator-token operation failed: {OperationName}.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                localizer["Common.Unavailable"]);
        }
    }
}
