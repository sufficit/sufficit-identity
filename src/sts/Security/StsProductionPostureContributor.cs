using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Reports permissive STS-owned production settings. Optional feature findings
/// are emitted only while the feature is enabled and the permissive branch can
/// affect runtime behavior.
/// </summary>
public sealed class StsProductionPostureContributor(
    SufficitIdentityOptions options,
    IConfiguration configuration,
    IDistributedCache? distributedCache = null)
    : IProductionPostureContributor
{
    public IEnumerable<ProductionPostureFinding> Evaluate()
    {
        if (options.Csp.Enabled && options.Csp.ReportOnly)
        {
            yield return new(
                "csp-report-only",
                "Content-Security-Policy is in Report-Only mode and does not block browser policy violations.",
                "Set Sufficit:Identity:Csp:ReportOnly=false after UI calibration.",
                options.Csp.AcknowledgeReportOnly);
        }

        if (options.PersonalTokens.Mode == SecurityPolicyEnforcementMode.Observe)
        {
            yield return new(
                "personal-tokens-observe",
                "Personal-token issuance policy is in Observe mode, so strict scope, lifetime and caller decisions are not enforced.",
                "Inventory current callers and set Sufficit:Identity:PersonalTokens:Mode=Enforce.");
        }

        if (!options.PersonalTokens.RequireMfa)
        {
            yield return new(
                "personal-tokens-mfa-disabled",
                "Personal-token issuance accepts a password-only authentication context for the sensitive personal_tokens.manage scope.",
                "Set Sufficit:Identity:PersonalTokens:RequireMfa=true, or document a time-bounded security exception.");
        }

        if (options.SharedSignals.Enabled
            && options.SharedSignals.StreamManagementEnabled
            && !options.SharedSignals.RequireMfa)
        {
            yield return new(
                "ssf-transmitter-mfa-disabled",
                "SSF stream management accepts a password-only authentication context for the sensitive ssf_transmitter scope.",
                "Set Sufficit:Identity:SharedSignals:RequireMfa=true, or document a time-bounded security exception.");
        }

        var tokenExchange = configuration
            .GetSection("Sufficit:Identity:TokenExchange")
            .Get<Grants.TokenExchangeOptions>()
            ?? new Grants.TokenExchangeOptions();
        // Provenance is evaluated on every exchange since eval 2026-08-30 (F-1),
        // so Observe mode is a permissive production default regardless of
        // whether an actor allow-list was configured.
        if (tokenExchange.Enabled
            && tokenExchange.ProvenanceMode
                == SecurityPolicyEnforcementMode.Observe)
        {
            yield return new(
                "token-exchange-provenance-observe",
                "Token-exchange subject-token provenance is in Observe mode, so subject tokens without an unambiguous authorized party are still accepted.",
                "Migrate subject tokens to an unambiguous azp/client_id and set TokenExchange:ProvenanceMode=Enforce.");
        }

        if (options.Ciba.Enabled
            && options.Ciba.ClientPolicyMode
                == SecurityPolicyEnforcementMode.Observe)
        {
            yield return new(
                "ciba-client-policy-observe",
                "CIBA client eligibility is in Observe mode and would-be denials are permitted.",
                "Provision the CIBA grant/client allow-list and set Ciba:ClientPolicyMode=Enforce.");
        }

        if (options.CredentialMutations.StepUpMode
            == CredentialMutationStepUpMode.Audit)
        {
            yield return new(
                "credential-mutations-step-up-audit",
                "Credential mutation step-up is in Audit mode, so stale sessions can retain compatibility access.",
                "Complete the reauthentication rollout and set CredentialMutations:StepUpMode=Enforce.");
        }

        if (options.PublicOrigin.Mode == PublicOriginMode.Audit
            && PublicOriginResolver.ResolveConfigured(options) is null)
        {
            yield return new(
                "public-origin-request-derived",
                "Public security URLs can be derived from the request host in compatibility Audit mode.",
                "Configure Sufficit:Identity:PublicUrl or Issuer and set PublicOrigin:Mode=Enforce.");
        }

        if (options.Dpop.Enabled
            && options.DistributedCache.RequireShared
            && distributedCache?.GetType().Name is "MemoryDistributedCache")
        {
            yield return new(
                "dpop-replay-cache-not-shared",
                "DPoP requires shared state but the registered distributed cache is process-local memory.",
                "Register a shared cache or set DistributedCache:RequireShared=false for a genuine single-replica deployment.");
        }

        // The deployment shape must be a statement, not an inherited default
        // (eval 2026-08-30, F-4). DeploymentTopology drives the proxy-trust,
        // shared-cache and issuer contract enforced by DeploymentTopologyPolicy;
        // while it silently defaults to SingleReplica, a host that is in fact
        // replicated keeps the process-local IDistributedCache and degrades the
        // state that has no database primary — DPoP nonce challenges,
        // front-channel logout context and passkey ceremony tickets — with no
        // signal at all. Requiring the key to be present makes that a decision
        // the deployment records rather than one it backs into.
        if (string.IsNullOrWhiteSpace(
            configuration["Sufficit:Identity:DeploymentTopology"]))
        {
            yield return new(
                "deployment-topology-undeclared",
                "Sufficit:Identity:DeploymentTopology is not declared, so the host silently assumes SingleReplica and keeps process-local state for DPoP nonces, front-channel logout context and passkey ceremonies.",
                "Declare Sufficit:Identity:DeploymentTopology explicitly (SingleReplica, Clustered, BehindTrustedProxy or ClusteredBehindTrustedProxy).");
        }
    }
}
