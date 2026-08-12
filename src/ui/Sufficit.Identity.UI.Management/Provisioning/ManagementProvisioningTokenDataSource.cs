using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Provisioning;

/// <summary>
/// Circuit-safe adapter for the one-time token reveal action. The presentation
/// layer does not persist the returned value or copy it into audit/log data;
/// The authorization server still keeps its reference-token record for validation and expiry.
/// </summary>
public sealed class ManagementProvisioningTokenDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementProvisioningTokenDataSource> logger)
{
    public async Task<ManagementDataResult<ProvisioningTokenIssueResult>>
        IssueAsync(
            int lifetimeSeconds,
            CancellationToken cancellationToken = default)
    {
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
                exception.Message,
                exception.Field,
                errorDetails: [
                    "Próximo passo: escolha uma validade entre 60 segundos e o limite configurado no Identity."
                ]);
        }
        catch (ManagementConflictException exception)
        {
            return ProvisioningErrorMessages.ConflictFailure<ProvisioningTokenIssueResult>(
                exception,
                "emitir o token temporário");
        }
        catch (ManagementAccessException exception)
        {
            return ProvisioningErrorMessages.AccessFailure<ProvisioningTokenIssueResult>(
                exception.Decision,
                "emitir o token temporário",
                ManagementCapabilities.ProvisioningApply);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Temporary provisioning-token issuance timed out.");
            return ManagementDataResult<ProvisioningTokenIssueResult>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.TimeoutMessage(
                    "emitir o token temporário"),
                errorDetails: [
                    "Próximo passo: confirme o estado do Identity em /health/ready e tente novamente."
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
                    "emitir o token temporário"),
                errorDetails: [
                    "Próximo passo: confirme que esta versão do Identity está implantada e que a emissão temporária foi habilitada pela infraestrutura."
                ]);
        }
    }
}
