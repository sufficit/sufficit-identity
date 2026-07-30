using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Scopes;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Scopes;

/// <summary>
/// Circuit-safe UI adapter over the canonical OpenIddict scope-management
/// service. The UI never talks to the scope store directly.
/// </summary>
public sealed class ManagementScopeDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementScopeDataSource> logger)
{
    public Task<ManagementDataResult<IReadOnlyList<ManagementScopeSummary>>>
        ListAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (scopes, context) => scopes.ListAsync(
                context,
                cancellationToken),
            "Scope listing",
            cancellationToken);

    public Task<ManagementDataResult<ManagementScopeDetail>> GetAsync(
        string id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (scopes, context) => scopes.GetAsync(
                id,
                context,
                cancellationToken),
            "Scope detail",
            cancellationToken);

    public Task<ManagementDataResult<ManagementScopeDetail>> CreateAsync(
        CreateManagementScopeCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (scopes, context) => scopes.CreateAsync(
                command,
                context,
                cancellationToken),
            "Scope creation",
            cancellationToken);

    public Task<ManagementDataResult<ManagementScopeDetail>> UpdateAsync(
        string id,
        UpdateManagementScopeCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (scopes, context) => scopes.UpdateAsync(
                id,
                command,
                context,
                cancellationToken),
            "Scope update",
            cancellationToken);

    public Task<ManagementDataResult<bool>> DeleteAsync(
        string id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (scopes, context) =>
            {
                await scopes.DeleteAsync(id, context, cancellationToken);
                return true;
            },
            "Scope deletion",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IScopeManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");

            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IScopeManagementService>();
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
                exception.Message);
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
            return ManagementDataResult<T>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui a capability necessária.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço demorou mais que o esperado. Tente novamente.");
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
                "O serviço de identidade não conseguiu concluir a operação.");
        }
    }
}
