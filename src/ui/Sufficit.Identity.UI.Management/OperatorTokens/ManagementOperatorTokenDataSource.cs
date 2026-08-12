using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.OperatorTokens;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.OperatorTokens;

/// <summary>
/// Circuit-safe adapter for the current operator's short-lived Management
/// tokens. Token values are returned only to the requesting component and are
/// never logged or retained by this adapter.
/// </summary>
public sealed class ManagementOperatorTokenDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementOperatorTokenDataSource> logger)
{
    public Task<ManagementDataResult<OperatorTokenWorkspace>> GetAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.GetWorkspaceAsync(
                context,
                cancellationToken),
            "consultar os tokens temporários",
            cancellationToken);

    public Task<ManagementDataResult<OperatorTokenIssueResult>> IssueAsync(
        IssueOperatorTokenCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (service, context) => service.IssueAsync(
                command,
                context,
                cancellationToken),
            "emitir o token temporário",
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
            "revogar o token temporário",
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
                exception.Message,
                exception.Field);
        }
        catch (ManagementConflictException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Conflict,
                exception.Message,
                errorDetails: [
                    "Confirme a política TemporaryOperatorToken do ambiente e tente novamente."
                ]);
        }
        catch (ManagementNotFoundException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.NotFound,
                exception.Message);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            var message = outcome is ManagementDataOutcome.StepUpRequired
                ? "Conclua a autenticação multifator e recarregue esta página."
                : "O operador atual não possui a capability necessária para esta operação.";
            return ManagementDataResult<T>.Failure(
                outcome,
                message,
                errorDetails: [
                    $"Motivo técnico: {exception.Decision.ReasonCode}."
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
                $"O Identity não respondeu a tempo ao tentar {operationName}.");
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
                $"Não foi possível {operationName}. Consulte os logs pelo correlation ID e tente novamente.");
        }
    }
}
