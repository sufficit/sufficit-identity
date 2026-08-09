using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS;

/// <summary>
/// Validates Google reCAPTCHA v2 or Cloudflare Turnstile responses at the
/// provider's server endpoint. Network/provider errors fail closed for the
/// protected public operation, without leaking their details to the caller.
/// </summary>
public sealed class RemoteHumanVerificationService(
    HttpClient httpClient,
    HumanVerificationOptions options,
    IHttpContextAccessor httpContextAccessor,
    ILogger<RemoteHumanVerificationService> logger,
    ISecretStore? secretStore = null)
    : IHumanVerificationService
{
    private static readonly Uri GoogleVerifyEndpoint = new(
        "https://www.google.com/recaptcha/api/siteverify");

    private static readonly Uri TurnstileVerifyEndpoint = new(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify");

    public HumanVerificationWidget GetWidget(HumanVerificationFlow flow)
    {
        var required = options.Protects(flow);
        return new HumanVerificationWidget(
            required,
            options.Provider,
            required ? options.SiteKey : null,
            ToAction(flow));
    }

    public async Task<HumanVerificationResult> VerifyAsync(
        HumanVerificationFlow flow,
        string? responseToken,
        CancellationToken cancellationToken = default)
    {
        if (!options.Protects(flow))
        {
            return HumanVerificationResult.Success;
        }

        if (string.IsNullOrWhiteSpace(responseToken))
        {
            return new(false, "missing-response");
        }

        var secret = secretStore is null
            ? options.SecretKey
            : await secretStore.GetSecretAsync(
                "identity/human-verification/secret-key",
                cancellationToken) ?? options.SecretKey;
        if (string.IsNullOrWhiteSpace(secret))
        {
            logger.LogError(
                "Human verification is enabled but its provider secret is unavailable from ISecretStore.");
            return new(false, "provider-not-configured");
        }

        var fields = new Dictionary<string, string>
        {
            ["secret"] = secret,
            ["response"] = responseToken,
        };

        var remoteIp = httpContextAccessor.HttpContext?
            .Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            fields["remoteip"] = remoteIp;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.RequestTimeoutSeconds));

        try
        {
            using var content = new FormUrlEncodedContent(fields);
            using var response = await httpClient.PostAsync(
                GetVerifyEndpoint(),
                content,
                timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "Human verification provider returned HTTP {StatusCode} for {Flow}.",
                    (int)response.StatusCode,
                    flow);
                return new(false, "provider-http-error");
            }

            var payload = await response.Content.ReadFromJsonAsync<VerifyResponse>(
                cancellationToken: timeout.Token);
            if (payload?.Success != true)
            {
                logger.LogInformation(
                    "Human verification rejected for {Flow}; codes: {ErrorCodes}.",
                    flow,
                    payload?.ErrorCodes is { Length: > 0 }
                        ? string.Join(',', payload.ErrorCodes)
                        : "none");
                return new(false, "challenge-rejected");
            }

            if (options.AllowedHostnames.Length > 0
                && (string.IsNullOrWhiteSpace(payload.Hostname)
                    || !options.AllowedHostnames.Contains(
                        payload.Hostname,
                        StringComparer.OrdinalIgnoreCase)))
            {
                logger.LogWarning(
                    "Human verification returned an unexpected hostname for {Flow}.",
                    flow);
                return new(false, "hostname-mismatch");
            }

            // Turnstile binds a challenge to the rendered action. Google
            // reCAPTCHA v2 does not emit an action value.
            if (options.Provider == HumanVerificationProvider.Turnstile
                && !string.Equals(
                    payload.Action,
                    ToAction(flow),
                    StringComparison.Ordinal))
            {
                logger.LogWarning(
                    "Human verification returned an unexpected action for {Flow}.",
                    flow);
                return new(false, "action-mismatch");
            }

            return HumanVerificationResult.Success;
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(
                "Human verification provider timed out for {Flow}.",
                flow);
            return new(false, "provider-timeout");
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(
                exception,
                "Human verification provider was unavailable for {Flow}.",
                flow);
            return new(false, "provider-unavailable");
        }
        catch (System.Text.Json.JsonException exception)
        {
            logger.LogWarning(
                exception,
                "Human verification provider returned invalid JSON for {Flow}.",
                flow);
            return new(false, "provider-invalid-response");
        }
    }

    private Uri GetVerifyEndpoint() => options.Provider switch
    {
        HumanVerificationProvider.GoogleRecaptchaV2 => GoogleVerifyEndpoint,
        HumanVerificationProvider.Turnstile => TurnstileVerifyEndpoint,
        _ => throw new InvalidOperationException(
            $"Unsupported human-verification provider '{options.Provider}'."),
    };

    private static string ToAction(HumanVerificationFlow flow) => flow switch
    {
        HumanVerificationFlow.Registration => "registration",
        HumanVerificationFlow.PasswordRecovery => "password_recovery",
        HumanVerificationFlow.EmailConfirmation => "email_confirmation",
        _ => throw new ArgumentOutOfRangeException(nameof(flow), flow, null),
    };

    private sealed class VerifyResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("hostname")]
        public string? Hostname { get; init; }

        [JsonPropertyName("action")]
        public string? Action { get; init; }

        [JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; init; }
    }
}
