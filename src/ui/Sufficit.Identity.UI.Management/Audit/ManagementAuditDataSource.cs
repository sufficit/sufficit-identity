using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Audit;

public sealed class ManagementAuditDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementAuditDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public async Task<ManagementDataResult<IReadOnlyList<ManagementAuditRecord>>>
        GetEventsAsync(
            int limit = 100,
            CancellationToken cancellationToken = default)
    {
        try
        {
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");

            await using var scope = scopeFactory.CreateAsyncScope();
            var audit = scope.ServiceProvider
                .GetRequiredService<IManagementAuditService>();

            return ManagementDataResult<IReadOnlyList<ManagementAuditRecord>>
                .Success(await audit.ListAsync(
                    context,
                    limit,
                    cancellationToken));
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<IReadOnlyList<ManagementAuditRecord>>
                .Failure(
                    outcome,
                    outcome is ManagementDataOutcome.StepUpRequired
                        ? localizer["Common.Access.StepUpRequired"]
                        : localizer["Common.Access.Forbidden"]);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Audit listing failed in the embedded management module.");
            return ManagementDataResult<IReadOnlyList<ManagementAuditRecord>>
                .Failure(
                    ManagementDataOutcome.Unavailable,
                    localizer["Common.Unavailable"]);
        }
    }
}
