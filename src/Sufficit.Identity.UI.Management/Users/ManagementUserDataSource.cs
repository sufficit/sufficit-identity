using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Users;

/// <summary>
/// Circuit-safe adapter over the canonical user-management application
/// contract. Claims, persistence and tenant rules remain outside the UI.
/// </summary>
public sealed class ManagementUserDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementUserDataSource> logger)
{
    public Task<ManagementDataResult<ManagementUserAccess>> GetAccessAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (users, context) => users.GetAccessAsync(
                context,
                cancellationToken),
            "User access discovery",
            cancellationToken);

    public Task<ManagementDataResult<ManagementUserPage>> SearchAsync(
        ManagementUserSearch query,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (users, context) => users.SearchAsync(
                query,
                context,
                cancellationToken),
            "User listing",
            cancellationToken);

    public Task<ManagementDataResult<ManagementUserDetail>> GetAsync(
        string id,
        string? contextId,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (users, context) => users.GetAsync(
                id,
                contextId,
                context,
                cancellationToken),
            "User detail",
            cancellationToken);

    public Task<ManagementDataResult<ManagementUserDetail>> CreateAsync(
        CreateManagementUserCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (users, context) => users.CreateAsync(
                command,
                context,
                cancellationToken),
            "User creation",
            cancellationToken);

    public Task<ManagementDataResult<ManagementUserDetail>> ResetPasswordAsync(
        string id,
        ResetManagementUserPasswordCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (users, context) => users.ResetPasswordAsync(
                id,
                command,
                context,
                cancellationToken),
            "User password reset",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IUserManagementService, ManagementRequestContext, Task<T>> operation,
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
            var users = scope.ServiceProvider
                .GetRequiredService<IUserManagementService>();
            return ManagementDataResult<T>.Success(
                await operation(users, context));
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
                    : "Sua conta não possui autoridade neste contexto.");
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
                "O serviço de identidade não conseguiu concluir a consulta.");
        }
    }
}
