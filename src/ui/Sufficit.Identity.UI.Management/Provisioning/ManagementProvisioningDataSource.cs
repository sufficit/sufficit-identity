using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Provisioning;

/// <summary>
/// Circuit-safe UI adapter over the canonical provisioning use case.
/// JSON parsing is a presentation concern; validation and persistence remain
/// in the shared application service.
/// </summary>
public sealed class ManagementProvisioningDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementProvisioningDataSource> logger)
{
    public const int MaxManifestLength = 262_144;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    public Task<ManagementDataResult<IdentityProvisioningPlan>> PreviewAsync(
        string manifestJson,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            manifestJson,
            (service, manifest, context) => service.PreviewAsync(
                manifest,
                context,
                cancellationToken),
            "Provisioning preview",
            cancellationToken);

    public Task<ManagementDataResult<IdentityProvisioningPlan>> ApplyAsync(
        string manifestJson,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            manifestJson,
            (service, manifest, context) => service.ApplyAsync(
                manifest,
                context,
                cancellationToken),
            "Provisioning apply",
            cancellationToken);

    private async Task<ManagementDataResult<IdentityProvisioningPlan>>
        ExecuteAsync(
            string manifestJson,
            Func<
                IProvisioningManagementService,
                IdentityProvisioningManifest,
                ManagementRequestContext,
                Task<IdentityProvisioningPlan>> operation,
            string operationName,
            CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(manifestJson))
        {
            return Invalid(
                "Informe o manifesto JSON.",
                "O documento não pode ficar vazio.");
        }

        if (manifestJson.Length > MaxManifestLength)
        {
            return Invalid(
                "O manifesto excede o limite permitido.",
                $"Use no máximo {MaxManifestLength:N0} caracteres.");
        }

        IdentityProvisioningManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<IdentityProvisioningManifest>(
                manifestJson,
                JsonOptions);
        }
        catch (JsonException exception)
        {
            return Invalid(
                "O JSON não pôde ser interpretado.",
                JsonError(exception));
        }

        if (manifest is null)
        {
            return Invalid(
                "Informe um objeto JSON válido.",
                "O valor JSON null não representa um manifesto.");
        }

        try
        {
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id
                    ?? $"management-ui-{Guid.NewGuid():N}");

            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IProvisioningManagementService>();
            return ManagementDataResult<IdentityProvisioningPlan>.Success(
                await operation(service, manifest, context));
        }
        catch (IdentityProvisioningManifestException exception)
        {
            return ManagementDataResult<IdentityProvisioningPlan>.Failure(
                ManagementDataOutcome.Invalid,
                "O manifesto não passou pela validação de segurança.",
                errorDetails: exception.Errors);
        }
        catch (ManagementConflictException exception)
        {
            return ProvisioningErrorMessages.ConflictFailure<IdentityProvisioningPlan>(
                exception,
                operationName);
        }
        catch (ManagementAccessException exception)
        {
            return ProvisioningErrorMessages.AccessFailure<IdentityProvisioningPlan>(
                exception.Decision,
                operationName,
                operationName is "Provisioning apply"
                    ? ManagementCapabilities.ProvisioningApply
                    : ManagementCapabilities.ProvisioningPreview);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<IdentityProvisioningPlan>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.TimeoutMessage(
                    operationName is "Provisioning apply"
                        ? "aplicar o manifesto"
                        : "gerar o preview"),
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
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<IdentityProvisioningPlan>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.DependencyMessage(
                    operationName is "Provisioning apply"
                        ? "aplicar o manifesto"
                        : "gerar o preview"),
                errorDetails: [
                    "Se o problema persistir, encaminhe o horário e o ID de correlação ao administrador do serviço."
                ]);
        }
    }

    private static ManagementDataResult<IdentityProvisioningPlan> Invalid(
        string message,
        string detail) =>
        ManagementDataResult<IdentityProvisioningPlan>.Failure(
            ManagementDataOutcome.Invalid,
            message,
            errorDetails: [detail]);

    private static string JsonError(JsonException exception)
    {
        var location = exception.LineNumber is null
            ? null
            : $"Linha {exception.LineNumber + 1}, coluna {(exception.BytePositionInLine ?? 0) + 1}.";
        return location
            ?? "Revise a sintaxe e os nomes das propriedades.";
    }
}
