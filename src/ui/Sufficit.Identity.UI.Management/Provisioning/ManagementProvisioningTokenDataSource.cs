using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Provisioning;

/// <summary>
/// Circuit-safe adapter for the one-time token reveal action. The presentation
/// layer does not persist the returned value or copy it into audit/log data;
/// The authorization server still keeps its reference-token record for validation and expiry.
/// </summary>
public sealed class ManagementProvisioningTokenDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementProvisioningTokenDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
{
    public async Task<ManagementDataResult<ProvisioningTokenIssueResult>>
        IssueAsync(
            int lifetimeSeconds,
            CancellationToken cancellationToken = default)
    {
        string operation = localizer["Provisioning.Operation.IssueTemporaryToken"];
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IProvisioningTokenManagementService>();
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id
                    ?? $"management-ui-{Guid.NewGuid():N}");

            return ManagementDataResult<ProvisioningTokenIssueResult>.Success(
                await service.IssueAsync(
                    context,
                    new ProvisioningTokenIssueRequest(lifetimeSeconds),
                    cancellationToken));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<ProvisioningTokenIssueResult>.Failure(
                ManagementDataOutcome.Invalid,
                ManagementErrorText.For(localizer, exception),
                exception.Field,
                errorDetails: [
                    localizer["Provisioning.Validation.LifetimeNextStep"]
                ]);
        }
        catch (ManagementConflictException exception)
        {
            return ProvisioningErrorMessages.ConflictFailure<ProvisioningTokenIssueResult>(
                localizer,
                exception,
                operation);
        }
        catch (ManagementAccessException exception)
        {
            return ProvisioningErrorMessages.AccessFailure<ProvisioningTokenIssueResult>(
                localizer,
                exception.Decision,
                operation,
                ManagementCapabilities.ProvisioningApply);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Temporary provisioning-token issuance timed out.");
            return ManagementDataResult<ProvisioningTokenIssueResult>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.TimeoutMessage(
                    localizer,
                    operation),
                errorDetails: [
                    localizer["Provisioning.NextStep.CheckHealth"]
                ]);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Temporary provisioning-token issuance failed in the embedded management module.");
            return ManagementDataResult<ProvisioningTokenIssueResult>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.DependencyMessage(
                    localizer,
                    operation),
                errorDetails: [
                    localizer["Provisioning.NextStep.ConfirmDeploymentEnabled"]
                ]);
        }
    }
}
