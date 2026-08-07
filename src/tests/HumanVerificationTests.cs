using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class HumanVerificationTests
{
    [Fact]
    public async Task Missing_response_fails_without_calling_provider()
    {
        var handler = new RecordingHandler("{\"success\":true}");
        var service = CreateService(handler, EnabledOptions());

        var result = await service.VerifyAsync(
            HumanVerificationFlow.Registration,
            null);

        Assert.False(result.Succeeded);
        Assert.Equal("missing-response", result.ErrorCode);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task Disabled_or_unprotected_flow_does_not_call_provider()
    {
        var handler = new RecordingHandler("{\"success\":true}");
        var options = new HumanVerificationOptions
        {
            Enabled = true,
            SiteKey = "site",
            SecretKey = "secret",
            ProtectedFlows = [nameof(HumanVerificationFlow.Registration)],
        };
        var service = CreateService(handler, options);

        var result = await service.VerifyAsync(
            HumanVerificationFlow.PasswordRecovery,
            null);

        Assert.True(result.Succeeded);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task Google_response_is_validated_server_side_with_remote_ip()
    {
        var handler = new RecordingHandler(
            "{\"success\":true,\"hostname\":\"identity.example.test\"}");
        var options = EnabledOptions();
        var service = CreateService(handler, options);

        var result = await service.VerifyAsync(
            HumanVerificationFlow.Registration,
            "browser-proof");

        Assert.True(result.Succeeded);
        Assert.Equal(
            "https://www.google.com/recaptcha/api/siteverify",
            handler.LastRequestUri?.ToString());
        Assert.Contains("secret=secret", handler.LastBody, StringComparison.Ordinal);
        Assert.Contains("response=browser-proof", handler.LastBody, StringComparison.Ordinal);
        Assert.Contains("remoteip=192.0.2.42", handler.LastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Turnstile_requires_the_expected_flow_action()
    {
        var handler = new RecordingHandler(
            "{\"success\":true,\"hostname\":\"identity.example.test\","
            + "\"action\":\"password_recovery\"}");
        var options = EnabledOptions(HumanVerificationProvider.Turnstile);
        var service = CreateService(handler, options);

        var result = await service.VerifyAsync(
            HumanVerificationFlow.Registration,
            "browser-proof");

        Assert.False(result.Succeeded);
        Assert.Equal("action-mismatch", result.ErrorCode);
        Assert.Equal(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            handler.LastRequestUri?.ToString());
    }

    [Fact]
    public async Task Unexpected_hostname_and_provider_failure_fail_closed()
    {
        var hostnameHandler = new RecordingHandler(
            "{\"success\":true,\"hostname\":\"wrong.example.test\"}");
        var hostnameResult = await CreateService(
            hostnameHandler,
            EnabledOptions()).VerifyAsync(
                HumanVerificationFlow.Registration,
                "browser-proof");

        var failureHandler = new RecordingHandler(
            "{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\"]}");
        var failureResult = await CreateService(
            failureHandler,
            EnabledOptions()).VerifyAsync(
                HumanVerificationFlow.Registration,
                "replayed-proof");

        Assert.False(hostnameResult.Succeeded);
        Assert.Equal("hostname-mismatch", hostnameResult.ErrorCode);
        Assert.False(failureResult.Succeeded);
        Assert.Equal("challenge-rejected", failureResult.ErrorCode);
    }

    [Fact]
    public void Enabled_configuration_requires_keys_and_known_flows()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new HumanVerificationOptions { Enabled = true }.Validate());

        var unknownFlow = new HumanVerificationOptions
        {
            Enabled = true,
            SiteKey = "site",
            SecretKey = "secret",
            ProtectedFlows = ["unknown-flow"],
        };
        Assert.Throws<InvalidOperationException>(unknownFlow.Validate);
    }

    private static HumanVerificationOptions EnabledOptions(
        HumanVerificationProvider provider =
            HumanVerificationProvider.GoogleRecaptchaV2) => new()
            {
                Enabled = true,
                Provider = provider,
                SiteKey = "site",
                SecretKey = "secret",
                AllowedHostnames = ["identity.example.test"],
            };

    private static RemoteHumanVerificationService CreateService(
        HttpMessageHandler handler,
        HumanVerificationOptions options)
    {
        options.Validate();
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.42");
        return new RemoteHumanVerificationService(
            new HttpClient(handler),
            options,
            new HttpContextAccessor { HttpContext = context },
            NullLogger<RemoteHumanVerificationService>.Instance);
    }

    private sealed class RecordingHandler(string responseJson)
        : HttpMessageHandler
    {
        public int CallCount { get; private set; }
        public Uri? LastRequestUri { get; private set; }
        public string LastBody { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            LastRequestUri = request.RequestUri;
            LastBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    responseJson,
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
