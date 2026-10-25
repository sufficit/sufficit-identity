using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Maintenance;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Maintenance;

/// <summary>
/// Circuit-safe adapter over the canonical management API boundary. It resolves a fresh scope per operation and never reads persistence directly.
/// </summary>
public sealed class ManagementMaintenanceDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementMaintenanceDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public Task<ManagementDataResult<TokenMaintenanceOverview>> GetAsync(
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.GetAsync(context, cancellationToken),
        "Token maintenance", cancellationToken);

    public Task<ManagementDataResult<bool>> SaveAsync(SaveTokenMaintenance command,
        CancellationToken cancellationToken = default) => ExecuteAsync(async (service, context) =>
        {
            await service.SaveAsync(command, context, cancellationToken);
            return true;
        }, "Token maintenance update", cancellationToken);

    public Task<ManagementDataResult<bool>> RequestAsync(string revision,
        CancellationToken cancellationToken = default) => ExecuteAsync(async (service, context) =>
        {
            await service.RequestRunAsync(revision, context, cancellationToken);
            return true;
        }, "Token maintenance request", cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<ITokenMaintenanceManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName, CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<ITokenMaintenanceManagementService>();
            var state = await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(state.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");
            return ManagementDataResult<T>.Success(await operation(service, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Invalid, ManagementErrorText.For(localizer, exception), exception.Field);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is ManagementAuthorizationOutcome.StepUpRequired
                ? ManagementDataOutcome.StepUpRequired : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? localizer["Common.Access.StepUpRequired"]
                    : localizer["Common.Access.Forbidden"]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, localizer["Common.Timeout"]);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            logger.LogError(exception, "{OperationName} failed.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, localizer["Common.Unavailable"]);
        }
    }
}
