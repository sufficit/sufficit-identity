using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Branding;

/// <summary>
/// Circuit-safe branding adapter. The embedded UI invokes the same application
/// use cases as the HTTP API and never resolves persistence services.
/// </summary>
public sealed class ManagementBrandingDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementBrandingDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public Task<ManagementDataResult<IReadOnlyList<ManagementBrandingTheme>>>
        GetThemesAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (branding, context) => branding.ListAsync(
                context,
                cancellationToken),
            "Branding listing",
            cancellationToken);

    public Task<ManagementDataResult<ManagementBrandingTheme>>
        CreateThemeAsync(
            SaveManagementBrandingThemeCommand command,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (branding, context) => branding.CreateAsync(
                command,
                context,
                cancellationToken),
            "Branding creation",
            cancellationToken);

    public Task<ManagementDataResult<ManagementBrandingTheme>>
        UpdateThemeAsync(
            int id,
            SaveManagementBrandingThemeCommand command,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (branding, context) => branding.UpdateAsync(
                id,
                command,
                context,
                cancellationToken),
            "Branding update",
            cancellationToken);

    public Task<ManagementDataResult<ManagementBrandingTheme>>
        ActivateThemeAsync(
            int id,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (branding, context) => branding.ActivateAsync(
                id,
                context,
                cancellationToken),
            "Branding activation",
            cancellationToken);

    public Task<ManagementDataResult<bool>> DeleteThemeAsync(
        int id,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (branding, context) =>
            {
                await branding.DeleteAsync(
                    id,
                    context,
                    cancellationToken);
                return true;
            },
            "Branding deletion",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IBrandingManagementService, ManagementRequestContext, Task<T>>
            operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var branding = scope.ServiceProvider
                .GetRequiredService<IBrandingManagementService>();
            var context = await CreateRequestContextAsync();

            return ManagementDataResult<T>.Success(
                await operation(branding, context));
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

    private async Task<ManagementRequestContext> CreateRequestContextAsync()
    {
        var authenticationState =
            await authenticationStateProvider.GetAuthenticationStateAsync();
        var correlationId = Activity.Current?.Id
            ?? $"management-ui-{Guid.NewGuid():N}";

        return new ManagementRequestContext(
            authenticationState.User,
            correlationId);
    }
}
