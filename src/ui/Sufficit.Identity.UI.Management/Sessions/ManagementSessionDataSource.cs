using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Sessions;

/// <summary>
/// Circuit-safe UI adapter over the canonical provider-session service.
/// </summary>
public sealed class ManagementSessionDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementSessionDataSource> logger,
    IStringLocalizer<ManagementResource> localizer)
{
    public Task<ManagementDataResult<ManagementSessionPage>> SearchAsync(
        ManagementSessionSearch query,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (sessions, context) => sessions.SearchAsync(
                query,
                context,
                cancellationToken),
            "Session listing",
            cancellationToken);

    public Task<ManagementDataResult<bool>> RevokeAsync(
        string id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (sessions, context) =>
            {
                await sessions.RevokeAsync(id, context, cancellationToken);
                return true;
            },
            "Session revocation",
            cancellationToken);

    public Task<ManagementDataResult<ManagementUserSessionRevocation>>
        RevokeAllForUserAsync(
            string userId,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (sessions, context) => sessions.RevokeAllForUserAsync(
                userId,
                context,
                cancellationToken),
            "Account session revocation",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<ISessionManagementService, ManagementRequestContext, Task<T>> operation,
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
                .GetRequiredService<ISessionManagementService>();
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
                ManagementErrorText.For(localizer, exception));
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
                    : localizer["Common.Access.Forbidden"]);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
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
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                localizer["Common.Unavailable"]);
        }
    }
}
