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
        // V12 (evaluation 2026-09-12): advisory by the maintainer's decision,
        // because the check calls an external service on every registration
        // and password change.
        if (!options.Password.RejectBreached)
        {
            yield return new(
                "password-breach-check-disabled",
                "New and changed passwords are not checked against known breached passwords.",
                "Set Sufficit:Identity:Password:RejectBreached=true.",
                Severity: ProductionPostureSeverity.Advisory);
        }
        else if (options.Password.BreachedCheckFailureMode == BreachedPasswordFailureMode.FailOpen)
        {
            yield return new(
                "password-breach-check-fail-open",
                "When the breached-password service cannot be reached, passwords are accepted without the check.",
                "Set Sufficit:Identity:Password:BreachedCheckFailureMode=FailClosed if blocking registration and password changes during an outage of that service is acceptable.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        if (options.Csp.Enabled && options.Csp.ReportOnly)
        {
            yield return new(
                "csp-report-only",
                "Content-Security-Policy is in Report-Only mode and does not block browser policy violations.",
                "Set Sufficit:Identity:Csp:ReportOnly=false after UI calibration.",
                options.Csp.AcknowledgeReportOnly);
        }

        if (!options.ExternalIdentities.RequireVerifiedEmail)
        {
            yield return new(
                "external-identity-unverified-email",
                "External providers may create accounts from email addresses no "
                + "one proved, which allows account pre-hijacking: whoever "
                + "registers a victim's address at a provider that does not "
                + "verify it keeps the binding after the victim proves it.",
                "Set Sufficit:Identity:ExternalIdentities:RequireVerifiedEmail=true, "
                + "or list the specific provider under TrustedEmailProviders when "
                + "it verifies addresses out of band.");
        }

        if (options.ExternalIdentities.TrustedEmailProviders.Count > 0)
        {
            yield return new(
                "external-identity-trusted-providers",
                "One or more external providers are trusted to assert email "
                + "ownership without proof: "
                + string.Join(
                    ", ",
                    options.ExternalIdentities.TrustedEmailProviders) + ".",
                "Confirm each listed provider verifies addresses before "
                + "asserting them; remove any that does not.");
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
                "Personal-token issuance accepts a password-only authentication context for the sensitive personal.tokens.manage scope.",
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
        // shared-cache and issuer contract enforced by DeploymentTopologyPolicy,
        // and that contract is only applied once a topology is DECLARED:
        // DistributedCache.RequireShared defaults to false, so a host that is in
        // fact replicated keeps the process-local IDistributedCache with no
        // signal at all. The three stores that used to depend on it — DPoP
        // nonces, front-channel logout context and passkey ceremonies — now have
        // a database primary, so the remaining exposure is the cache layer
        // itself and anything a deployment later puts on it. Requiring the key
        // makes the shape a decision the deployment records rather than one it
        // backs into.
        if (string.IsNullOrWhiteSpace(
            configuration["Sufficit:Identity:DeploymentTopology"]))
        {
            yield return new(
                "deployment-topology-undeclared",
                "Sufficit:Identity:DeploymentTopology is not declared, so the host silently assumes SingleReplica and never applies the clustered contract — the distributed cache stays process-local even when the deployment is replicated.",
                "Declare Sufficit:Identity:DeploymentTopology explicitly (SingleReplica, Clustered, BehindTrustedProxy or ClusteredBehindTrustedProxy).");
        }

        // A grant outside the OAuth 2.1 baseline is a deliberate, dated
        // decision or it is a regression. This one is blocking because it has
        // already been both: ROPC was found enabled in a configuration file
        // that nobody meant to ship (evaluation 2026-08-15, H-1), and a
        // startup gate would have caught it at the boot that introduced it.
        var legacy = new List<string>();
        if (options.LegacyGrants.Password)
        {
            legacy.Add("password (ROPC)");
        }

        if (options.LegacyGrants.None)
        {
            legacy.Add("none (implicit access token)");
        }

        if (legacy.Count > 0)
        {
            yield return new(
                "legacy-grants-enabled",
                "Grants outside the OAuth 2.1 baseline are enabled: "
                + string.Join(", ", legacy)
                + ". They issue tokens without the protections the current "
                + "baseline assumes.",
                "Migrate the remaining consumers and set "
                + "Sufficit:Identity:LegacyGrants:Password=false and "
                + "Sufficit:Identity:LegacyGrants:None=false, or acknowledge "
                + "this finding for the bounded migration window.");
        }

        // Deliberately not "the allow-list is empty": empty is the documented
        // default and the OpenIddict grant permission is already a boundary,
        // so that finding would fire on every deployment and teach operators
        // to skim the list. What has no signal behind it is the grant being
        // ON without anyone saying so.
        if (tokenExchange.Enabled
            && tokenExchange.AllowedClientIds.Count == 0
            && string.IsNullOrWhiteSpace(
                configuration["Sufficit:Identity:TokenExchange:Enabled"]))
        {
            yield return new(
                "token-exchange-enabled-by-default",
                "RFC 8693 token exchange is serving because it defaults to on, "
                + "not because this deployment enabled it, and no actor "
                + "allow-list narrows which applications may exchange tokens.",
                "Declare Sufficit:Identity:TokenExchange:Enabled explicitly. If "
                + "it stays on, list the exchanging applications under "
                + "AllowedClientIds so a mis-provisioned grant permission is not "
                + "sufficient on its own.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        if (options.Csp.Enabled)
        {
            var permissive = PermissiveCspSources(options.Csp.Policy).ToArray();
            if (permissive.Length > 0)
            {
                yield return new(
                    "csp-policy-permissive-source",
                    "The Content-Security-Policy allows sources that defeat the "
                    + "directive they are in: "
                    + string.Join("; ", permissive) + ".",
                    "Replace the wildcard, bare scheme or unsafe keyword with the "
                    + "specific origins the UI actually loads, in "
                    + "Sufficit:Identity:Csp:Policy.",
                    // Report-only, the policy blocks nothing yet, so a weak
                    // source is a calibration problem rather than a live hole.
                    Severity: options.Csp.ReportOnly
                        ? ProductionPostureSeverity.Advisory
                        : ProductionPostureSeverity.Blocking);
            }
        }

        if (!options.Certificates.RequirePurposeSeparation
            && SharesCertificatePath(options.Certificates))
        {
            // Advisory, not blocking: production is in exactly this state and
            // cannot leave it yet — the runtime rejects every replacement PFX
            // generated off the server (see the PFX investigation activity).
            // Refusing startup here would take the service down over a
            // condition its operators already know about and cannot resolve.
            yield return new(
                "certificate-purpose-not-separated",
                "The same certificate file is configured for token signing and "
                + "token encryption, so one key compromise costs authenticity "
                + "and confidentiality together.",
                "Provision a dedicated encryption certificate, point "
                + "Sufficit:Identity:Certificates:EncryptionPath at it and set "
                + "RequirePurposeSeparation=true.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        if (!options.Passkeys.RequireUserVerification)
        {
            yield return new(
                "passkey-user-verification-optional",
                "Passkey ceremonies do not require user verification, so a "
                + "passkey sign-in proves possession of the authenticator and "
                + "not that the account owner is present.",
                "Set Sufficit:Identity:Passkeys:RequireUserVerification=true. "
                + "While it is off the server correctly stops claiming amr=mfa "
                + "for those sign-ins, so any policy demanding a second factor "
                + "will ask for one.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        if (options.ClaimScopeMap.IncludeUnmappedClaimsInAccessTokens)
        {
            yield return new(
                "access-token-unmapped-claims",
                "Claims with no scope mapping are released into access tokens, "
                + "so a claim added for one consumer reaches every audience.",
                "Inventory the claims in production, give each a required scope "
                + "and destination, then set "
                + "Sufficit:Identity:ClaimScopeMap:IncludeUnmappedClaimsInAccessTokens=false.",
                Severity: ProductionPostureSeverity.Advisory);
        }
    }

    /// <summary>
    /// Sources in <c>script-src</c> and <c>connect-src</c> that make the
    /// directive meaningless: a wildcard, a bare scheme, or an unsafe keyword.
    /// </summary>
    private static IEnumerable<string> PermissiveCspSources(string? policy)
    {
        if (string.IsNullOrWhiteSpace(policy))
        {
            yield break;
        }

        foreach (var directive in policy.Split(
            ';',
            StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries))
        {
            var parts = directive.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries
                    | StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            var name = parts[0];
            if (name is not ("script-src" or "connect-src"))
            {
                continue;
            }

            foreach (var source in parts.Skip(1))
            {
                if (IsPermissiveSource(source))
                {
                    yield return $"{name} allows {source}";
                }
            }
        }
    }

    private static bool IsPermissiveSource(string source) =>
        source == "*"
        || source.StartsWith("*.", StringComparison.Ordinal)
        // A bare scheme such as "https:" permits every host on it.
        || (source.EndsWith(":", StringComparison.Ordinal)
            && !source.Contains("//", StringComparison.Ordinal))
        || source.Equals("'unsafe-inline'", StringComparison.OrdinalIgnoreCase)
        || source.Equals("'unsafe-eval'", StringComparison.OrdinalIgnoreCase);

    private static bool SharesCertificatePath(CertificatesOptions certificates)
    {
        var signing = CertificatePaths(
            certificates.SigningPath,
            certificates.SigningPaths);
        var encryption = CertificatePaths(
            certificates.EncryptionPath,
            certificates.EncryptionPaths);
        return signing.Count > 0
            && encryption.Count > 0
            && signing.Overlaps(encryption);
    }

    private static HashSet<string> CertificatePaths(
        string? single,
        IEnumerable<string> many) =>
        new(
            many.Prepend(single ?? string.Empty)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => Path.GetFullPath(path.Trim())),
            // The comparison is about the same file being named twice, so it
            // follows the platform's own idea of path equality.
            OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal);
}
