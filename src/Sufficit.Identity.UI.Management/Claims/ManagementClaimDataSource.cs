using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Claims;

/// <summary>
/// Circuit-safe UI adapter over the canonical claim-management service.
/// Persistence, authorization and token invalidation remain in the Identity
/// application layer.
/// </summary>
public sealed class ManagementClaimDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementClaimDataSource> logger)
{
    public Task<ManagementDataResult<ManagementClaimMetadata>> GetMetadataAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (claims, context) => claims.GetMetadataAsync(
                context,
                cancellationToken),
            "Claim metadata",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClaimPage>> SearchAsync(
        ManagementClaimSearch query,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (claims, context) => claims.SearchAsync(
                query,
                context,
                cancellationToken),
            "Claim listing",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClaimAssignment>> GetAsync(
        int id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (claims, context) => claims.GetAsync(
                id,
                context,
                cancellationToken),
            "Claim detail",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClaimAssignment>> CreateAsync(
        CreateManagementClaimCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (claims, context) => claims.CreateAsync(
                command,
                context,
                cancellationToken),
            "Claim assignment",
            cancellationToken);

    public Task<ManagementDataResult<bool>> DeleteAsync(
        int id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (claims, context) =>
            {
                await claims.DeleteAsync(id, context, cancellationToken);
                return true;
            },
            "Claim removal",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IClaimManagementService, ManagementRequestContext, Task<T>> operation,
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
                .GetRequiredService<IClaimManagementService>();
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
