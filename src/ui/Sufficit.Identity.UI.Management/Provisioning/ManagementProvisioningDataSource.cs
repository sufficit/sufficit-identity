using System.Diagnostics;
using System.Text.Json;
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
/// Circuit-safe UI adapter over the canonical provisioning use case.
/// JSON parsing is a presentation concern; validation and persistence remain
/// in the shared application service.
/// </summary>
public sealed class ManagementProvisioningDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementProvisioningDataSource> logger,
    IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer)
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
                localizer["Provisioning.Validation.ManifestRequired"],
                localizer["Provisioning.Validation.ManifestRequiredDetail"]);
        }

        if (manifestJson.Length > MaxManifestLength)
        {
            return Invalid(
                localizer["Provisioning.Validation.ManifestTooLarge"],
                localizer["Common.Validation.MaxLength", MaxManifestLength.ToString("N0")]);
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
                localizer["Provisioning.Validation.JsonInvalid"],
                JsonError(exception));
        }

        if (manifest is null)
        {
            return Invalid(
                localizer["Provisioning.Validation.ManifestObjectRequired"],
                localizer["Provisioning.Validation.ManifestNullDetail"]);
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
                localizer["Provisioning.Validation.SecurityValidationFailed"],
                errorDetails: exception.Errors);
        }
        catch (ManagementConflictException exception)
        {
            return ProvisioningErrorMessages.ConflictFailure<IdentityProvisioningPlan>(
                localizer,
                exception,
                operationName);
        }
        catch (ManagementAccessException exception)
        {
            return ProvisioningErrorMessages.AccessFailure<IdentityProvisioningPlan>(
                localizer,
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
                    localizer,
                    operationName is "Provisioning apply"
                        ? localizer["Provisioning.Operation.ApplyManifest"]
                        : localizer["Provisioning.Operation.GeneratePreview"]),
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
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<IdentityProvisioningPlan>.Failure(
                ManagementDataOutcome.Unavailable,
                ProvisioningErrorMessages.DependencyMessage(
                    localizer,
                    operationName is "Provisioning apply"
                        ? localizer["Provisioning.Operation.ApplyManifest"]
                        : localizer["Provisioning.Operation.GeneratePreview"]),
                errorDetails: [
                    localizer["Provisioning.NextStep.ForwardCorrelationId"]
                ]);
        }
    }

    private ManagementDataResult<IdentityProvisioningPlan> Invalid(
        string message,
        string detail) =>
        ManagementDataResult<IdentityProvisioningPlan>.Failure(
            ManagementDataOutcome.Invalid,
            message,
            errorDetails: [detail]);

    private string JsonError(JsonException exception)
    {
        var location = exception.LineNumber is null
            ? null
            : localizer[
                "Provisioning.Validation.JsonInvalidLocation",
                exception.LineNumber + 1,
                (exception.BytePositionInLine ?? 0) + 1].Value;
        return location
            ?? localizer["Provisioning.Validation.JsonInvalidGeneric"];
    }
}
