using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Claims;

/// <summary>
/// Circuit-safe UI adapter over the canonical claim-management service.
/// Persistence, authorization and token invalidation remain in the Identity
/// application layer.
/// </summary>
public sealed class ManagementClaimDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementClaimDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
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

    public Task<ManagementDataResult<ManagementClaimAssignment>> UpdateAsync(
        int id,
        UpdateManagementClaimCommand command,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (claims, context) => claims.UpdateAsync(
                id,
                command,
                context,
                cancellationToken),
            "Claim update",
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
