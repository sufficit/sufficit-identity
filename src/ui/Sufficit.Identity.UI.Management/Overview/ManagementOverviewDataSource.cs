using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Overview;

/// <summary>
/// Circuit-safe adapter for canonical management runtime discovery.
/// </summary>
public sealed class ManagementOverviewDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementOverviewDataSource> logger)
{
    public async Task<ManagementDataResult<ManagementOverview>> GetAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var overview = scope.ServiceProvider
                .GetRequiredService<IManagementOverviewService>();
            var authenticationState =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authenticationState.User,
                Activity.Current?.Id
                    ?? $"management-ui-{Guid.NewGuid():N}");

            return ManagementDataResult<ManagementOverview>.Success(
                await overview.GetAsync(context, cancellationToken));
        }
        catch (ManagementAccessException exception)
        {
            logger.LogWarning(
                "Management overview authorization denied: outcome={Outcome}; "
                + "reason={ReasonCode}.",
                exception.Decision.Outcome,
                exception.Decision.ReasonCode);
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<ManagementOverview>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui autoridade administrativa.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Management runtime discovery timed out.");
            return ManagementDataResult<ManagementOverview>.Failure(
                ManagementDataOutcome.Unavailable,
                "O runtime demorou mais que o esperado. Tente novamente.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Management runtime discovery failed in the embedded module.");
            return ManagementDataResult<ManagementOverview>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço de identidade não conseguiu informar seu estado.");
        }
    }
}
