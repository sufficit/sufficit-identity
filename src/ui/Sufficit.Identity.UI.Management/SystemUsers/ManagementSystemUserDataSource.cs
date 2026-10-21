using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.SystemUsers;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.SystemUsers;

/// <summary>
/// Circuit-safe adapter for system users. Enrollment codes are returned only
/// to the requesting component and are never logged or retained here.
/// </summary>
public sealed class ManagementSystemUserDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementSystemUserDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public Task<ManagementDataResult<IReadOnlyList<SystemUserSummary>>> ListAsync(CancellationToken ct = default) =>
        ExecuteAsync((service, context) => service.ListAsync(context, ct), "list system users", ct);

    public Task<ManagementDataResult<SystemUserSummary>> CreateAsync(
        CreateSystemUserCommand command, CancellationToken ct = default) =>
        ExecuteAsync((service, context) => service.CreateAsync(command, context, ct), "create system user", ct);

    public Task<ManagementDataResult<SystemUserSummary>> ToggleAsync(
        string userId, bool? enabled, CancellationToken ct = default) =>
        ExecuteAsync((service, context) => service.ToggleAsync(userId, enabled, context, ct), "toggle system user", ct);

    public Task<ManagementDataResult<IReadOnlyList<SystemUserEnrollmentSummary>>> ListEnrollmentsAsync(
        string userId, CancellationToken ct = default) =>
        ExecuteAsync((service, context) => service.ListEnrollmentsAsync(userId, context, ct), "list enrollments", ct);

    public Task<ManagementDataResult<SystemUserEnrollmentIssueResult>> IssueEnrollmentAsync(
        string userId, IssueSystemUserEnrollmentCommand command, CancellationToken ct = default) =>
        ExecuteAsync((service, context) => service.IssueEnrollmentAsync(userId, command, context, ct),
            "issue enrollment", ct);

    public Task<ManagementDataResult<bool>> RevokeEnrollmentAsync(
        string userId, Guid enrollmentId, CancellationToken ct = default) =>
        ExecuteAsync(async (service, context) =>
        {
            await service.RevokeEnrollmentAsync(userId, enrollmentId, context, ct);
            return true;
        }, "revoke enrollment", ct);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<ISystemUserManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<ISystemUserManagementService>();
            var authentication = await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");
            return ManagementDataResult<T>.Success(await operation(service, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Invalid, ManagementErrorText.For(localizer, exception), exception.Field);
        }
        catch (ManagementConflictException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Conflict, ManagementErrorText.For(localizer, exception));
        }
        catch (ManagementNotFoundException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.NotFound, ManagementErrorText.For(localizer, exception));
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is ManagementAuthorizationOutcome.StepUpRequired
                ? ManagementDataOutcome.StepUpRequired
                : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? localizer["Common.Access.StepUpRequired"]
                    : localizer["Common.Access.Forbidden"]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("System user operation timed out: {OperationName}.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, localizer["Common.Timeout"]);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "System user operation failed: {OperationName}.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, localizer["Common.Unavailable"]);
        }
    }
}
