namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Public flows that can require proof that the caller is a person. Keeping
/// these names provider-neutral prevents account code from depending on a
/// specific CAPTCHA vendor.
/// </summary>
public enum HumanVerificationFlow
{
    Registration,
    PasswordRecovery,
    EmailConfirmation,
}

public enum HumanVerificationProvider
{
    GoogleRecaptchaV2,
    Turnstile,
}

/// <summary>
/// Runtime options bound from <c>Sufficit:Identity:HumanVerification</c>.
/// Secrets belong in the environment/machine override, never in source.
/// </summary>
public sealed class HumanVerificationOptions
{
    public bool Enabled { get; init; }

    public HumanVerificationProvider Provider { get; init; } =
        HumanVerificationProvider.GoogleRecaptchaV2;

    public string? SiteKey { get; init; }

    public string? SecretKey { get; init; }

    public int RequestTimeoutSeconds { get; init; } = 5;

    public string[] ProtectedFlows { get; init; } =
    [
        nameof(HumanVerificationFlow.Registration),
        nameof(HumanVerificationFlow.PasswordRecovery),
        nameof(HumanVerificationFlow.EmailConfirmation),
    ];

    /// <summary>
    /// Optional exact host allow-list for the hostname returned by the
    /// provider. Empty preserves provider-side domain validation only.
    /// </summary>
    public string[] AllowedHostnames { get; init; } = [];

    public bool Protects(HumanVerificationFlow flow) =>
        Enabled && ProtectedFlows.Contains(
            flow.ToString(),
            StringComparer.OrdinalIgnoreCase);

    public void Validate()
    {
        if (!Enabled)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(SiteKey)
            || string.IsNullOrWhiteSpace(SecretKey))
        {
            throw new InvalidOperationException(
                "Human verification is enabled but SiteKey/SecretKey is missing.");
        }

        if (RequestTimeoutSeconds is < 1 or > 30)
        {
            throw new InvalidOperationException(
                "HumanVerification:RequestTimeoutSeconds must be between 1 and 30.");
        }

        foreach (var configured in ProtectedFlows)
        {
            if (!Enum.TryParse<HumanVerificationFlow>(
                    configured,
                    ignoreCase: true,
                    out _))
            {
                throw new InvalidOperationException(
                    $"Unknown human-verification flow '{configured}'.");
            }
        }
    }
}

public sealed record HumanVerificationWidget(
    bool Required,
    HumanVerificationProvider Provider,
    string? SiteKey,
    string Action);

public sealed record HumanVerificationResult(
    bool Succeeded,
    string? ErrorCode = null)
{
    public static HumanVerificationResult Success { get; } = new(true);
}

/// <summary>
/// Server-side boundary for human-verification providers. Browser callbacks
/// alone are never trusted.
/// </summary>
public interface IHumanVerificationService
{
    HumanVerificationWidget GetWidget(HumanVerificationFlow flow);

    Task<HumanVerificationResult> VerifyAsync(
        HumanVerificationFlow flow,
        string? responseToken,
        CancellationToken cancellationToken = default);
}
