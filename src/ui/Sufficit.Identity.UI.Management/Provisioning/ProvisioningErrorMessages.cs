using Microsoft.Extensions.Localization;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Provisioning;

/// <summary>
/// Turns authorization and dependency outcomes into operator-facing guidance.
/// Internal reason codes remain available as secondary support details without
/// becoming the primary message.
/// </summary>
internal static class ProvisioningErrorMessages
{
    public static ManagementDataResult<T> AccessFailure<T>(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        ManagementAuthorizationDecision decision,
        string operation,
        string capability) =>
        ManagementDataResult<T>.Failure(
            ToOutcome(decision),
            AccessMessage(localizer, decision, operation, capability),
            errorDetails: [AccessNextStep(localizer, decision, capability)]);

    public static ManagementDataResult<T> ConflictFailure<T>(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        ManagementConflictException exception,
        string operation) =>
        ManagementDataResult<T>.Failure(
            ManagementDataOutcome.Conflict,
            ManagementErrorText.For(localizer, exception),
            errorDetails: [ConflictNextStep(localizer, exception, operation)]);

    public static string TimeoutMessage(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        string operation) =>
        localizer["Provisioning.Error.Timeout", operation].Value;

    public static string DependencyMessage(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        string operation) =>
        localizer["Provisioning.Error.Dependency", operation].Value;

    private static ManagementDataOutcome ToOutcome(
        ManagementAuthorizationDecision decision) =>
        decision.Outcome is ManagementAuthorizationOutcome.StepUpRequired
            ? ManagementDataOutcome.StepUpRequired
            : ManagementDataOutcome.Forbidden;

    private static string AccessMessage(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        ManagementAuthorizationDecision decision,
        string operation,
        string capability) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                localizer["Provisioning.Error.NoAuthenticatedSession", operation].Value,
            "capability_not_granted" =>
                localizer["Provisioning.Error.CapabilityMissing", capability, operation].Value,
            "mfa_required" =>
                localizer["Provisioning.Error.MfaRequired", operation].Value,
            "temporary_token_cannot_mint" =>
                localizer["Provisioning.Error.TemporaryTokenCannotMint"].Value,
            _ =>
                localizer["Provisioning.Error.SecurityRuleRefused", operation].Value
        };

    private static string AccessNextStep(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        ManagementAuthorizationDecision decision,
        string capability) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                localizer["Provisioning.NextStep.Login"].Value,
            "capability_not_granted" =>
                localizer["Provisioning.NextStep.AssignCapability", capability].Value,
            "mfa_required" =>
                localizer["Provisioning.NextStep.CompleteMfa"].Value,
            "temporary_token_cannot_mint" =>
                localizer["Provisioning.NextStep.ReauthenticateOperator"].Value,
            _ => localizer["Provisioning.NextStep.SupportCode", decision.ReasonCode].Value
        };

    private static string ConflictNextStep(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer,
        ManagementConflictException exception,
        string operation) =>
        exception.ReasonCode switch
        {
            "temporary_provisioning_token_disabled" =>
                localizer["Provisioning.Conflict.TemporaryTokenDisabled"].Value,
            "temporary_provisioning_token_issuer_missing" =>
                localizer["Provisioning.Conflict.IssuerMissing"].Value,
            "provisioning_secret_unavailable" =>
                localizer["Provisioning.Conflict.SecretUnavailable"].Value,
            _ =>
                localizer["Provisioning.Conflict.CheckConfiguration", operation].Value
        };
}
