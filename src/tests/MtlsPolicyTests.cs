using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Mtls;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MtlsPolicyTests
{
    [Fact]
    public void Certificate_must_be_explicitly_bound_to_the_requesting_client()
    {
        using var certificate = CreateCertificate();
        var thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        var policy = new MtlsClientCertificatePolicy(new MtlsOptions
        {
            Enabled = true,
            DeploymentMode = MtlsDeploymentMode.DirectTls,
            RequireValidCertificateChain = false,
            ClientCertificateThumbprints = new Dictionary<string, HashSet<string>>
            {
                ["bound-client"] = new(StringComparer.Ordinal) { thumbprint },
            },
        });
        var context = new DefaultHttpContext();
        context.Connection.ClientCertificate = certificate;

        var bound = policy.Evaluate(context, "bound-client");
        var other = policy.Evaluate(context, "other-client");

        Assert.True(bound.Allowed);
        Assert.False(other.Allowed);
        Assert.Equal("certificate_not_bound_to_client", other.ReasonCode);
    }

    [Fact]
    public async Task Enabling_mtls_without_deployment_attestation_fails_startup()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mtls:Enabled"] = "true",
            });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ((IAsyncLifetime)factory).InitializeAsync());

        Assert.Contains("DeploymentMode", exception.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(MtlsCertificateRevocationMode.NoCheck, X509RevocationMode.NoCheck)]
    [InlineData(MtlsCertificateRevocationMode.Online, X509RevocationMode.Online)]
    [InlineData(MtlsCertificateRevocationMode.Offline, X509RevocationMode.Offline)]
    public void Revocation_mode_maps_to_the_platform_chain_policy(
        MtlsCertificateRevocationMode configured,
        X509RevocationMode expected) =>
        Assert.Equal(
            expected,
            SystemMtlsCertificateChainValidator.ToPlatformMode(configured));

    [Fact]
    public void Explicit_revocation_is_always_denied()
    {
        using var certificate = CreateCertificate();
        var policy = CreatePolicy(
            certificate,
            MtlsRevocationFailureMode.AllowWhenUnavailable,
            X509ChainStatusFlags.Revoked);

        var decision = policy.Evaluate(ContextWith(certificate), "bound-client");

        Assert.False(decision.Allowed);
        Assert.Equal("certificate_revoked", decision.ReasonCode);
    }

    [Fact]
    public void Revocation_endpoint_unavailability_fails_closed_by_default()
    {
        using var certificate = CreateCertificate();
        var policy = CreatePolicy(
            certificate,
            MtlsRevocationFailureMode.FailClosed,
            X509ChainStatusFlags.RevocationStatusUnknown
                | X509ChainStatusFlags.OfflineRevocation);

        var decision = policy.Evaluate(ContextWith(certificate), "bound-client");

        Assert.False(decision.Allowed);
        Assert.Equal("certificate_revocation_unavailable", decision.ReasonCode);
    }

    [Fact]
    public void Availability_mode_only_allows_pure_revocation_unavailability()
    {
        using var certificate = CreateCertificate();
        var unavailable = CreatePolicy(
            certificate,
            MtlsRevocationFailureMode.AllowWhenUnavailable,
            X509ChainStatusFlags.RevocationStatusUnknown);
        var untrusted = CreatePolicy(
            certificate,
            MtlsRevocationFailureMode.AllowWhenUnavailable,
            X509ChainStatusFlags.RevocationStatusUnknown
                | X509ChainStatusFlags.UntrustedRoot);

        var allowed = unavailable.Evaluate(
            ContextWith(certificate),
            "bound-client");
        var denied = untrusted.Evaluate(
            ContextWith(certificate),
            "bound-client");

        Assert.True(allowed.Allowed);
        Assert.Equal(
            "certificate_revocation_unavailable_allowed",
            allowed.ReasonCode);
        Assert.False(denied.Allowed);
        Assert.Equal("certificate_chain_invalid", denied.ReasonCode);
    }

    [Fact]
    public void Expired_certificate_is_denied_before_chain_fallback()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddHours(-2),
            DateTimeOffset.UtcNow.AddHours(-1));
        var policy = CreatePolicy(
            certificate,
            MtlsRevocationFailureMode.AllowWhenUnavailable,
            X509ChainStatusFlags.RevocationStatusUnknown);

        var decision = policy.Evaluate(ContextWith(certificate), "bound-client");

        Assert.False(decision.Allowed);
        Assert.Equal("certificate_not_current", decision.ReasonCode);
    }

    [Fact]
    public async Task Forwarded_certificate_is_accepted_only_from_a_dedicated_trusted_proxy()
    {
        using var certificate = CreateCertificate();
        var encoded = Convert.ToBase64String(
            certificate.Export(X509ContentType.Cert));
        var options = new MtlsOptions
        {
            Enabled = true,
            DeploymentMode = MtlsDeploymentMode.TrustedProxy,
            TrustedProxyNetworks = new(StringComparer.Ordinal) { "10.20.0.0/16" },
        };
        var networks = MtlsClientCertificateForwarding.ParseNetworks(
            options.TrustedProxyNetworks);
        var trusted = new DefaultHttpContext();
        trusted.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.20.1.2");
        trusted.Request.Headers[options.ForwardedCertificateHeader] = encoded;
        var trustedNext = false;

        await MtlsClientCertificateForwarding.InvokeAsync(
            trusted,
            () =>
            {
                trustedNext = true;
                return Task.CompletedTask;
            },
            options,
            networks,
            NullLogger.Instance);

        Assert.True(trustedNext);
        Assert.NotNull(trusted.Connection.ClientCertificate);
        Assert.Equal(
            certificate.GetCertHashString(HashAlgorithmName.SHA256),
            trusted.Connection.ClientCertificate.GetCertHashString(
                HashAlgorithmName.SHA256));
        Assert.False(trusted.Request.Headers.ContainsKey(
            options.ForwardedCertificateHeader));

        var untrusted = new DefaultHttpContext();
        untrusted.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.0.2.10");
        untrusted.Connection.ClientCertificate = certificate;
        untrusted.Request.Headers[options.ForwardedCertificateHeader] = encoded;
        await MtlsClientCertificateForwarding.InvokeAsync(
            untrusted,
            () => Task.CompletedTask,
            options,
            networks,
            NullLogger.Instance);

        Assert.Null(untrusted.Connection.ClientCertificate);
        Assert.False(untrusted.Request.Headers.ContainsKey(
            options.ForwardedCertificateHeader));

        var malformed = new DefaultHttpContext();
        malformed.Connection.RemoteIpAddress =
            System.Net.IPAddress.Parse("10.20.1.3");
        malformed.Request.Headers[options.ForwardedCertificateHeader] =
            "not-a-certificate";
        var malformedNext = false;
        await MtlsClientCertificateForwarding.InvokeAsync(
            malformed,
            () =>
            {
                malformedNext = true;
                return Task.CompletedTask;
            },
            options,
            networks,
            NullLogger.Instance);

        Assert.False(malformedNext);
        Assert.Equal(StatusCodes.Status400BadRequest, malformed.Response.StatusCode);
    }

    [Fact]
    public async Task Direct_tls_strips_a_forged_forwarded_certificate_header()
    {
        var options = new MtlsOptions
        {
            Enabled = true,
            DeploymentMode = MtlsDeploymentMode.DirectTls,
        };
        var context = new DefaultHttpContext();
        context.Request.Headers[options.ForwardedCertificateHeader] = "forged";

        await MtlsClientCertificateForwarding.InvokeAsync(
            context,
            () => Task.CompletedTask,
            options,
            [],
            NullLogger.Instance);

        Assert.Null(context.Connection.ClientCertificate);
        Assert.False(context.Request.Headers.ContainsKey(
            options.ForwardedCertificateHeader));
    }

    [Fact]
    public async Task Trusted_proxy_mode_without_a_dedicated_network_fails_startup()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mtls:Enabled"] = "true",
                ["Sufficit:Identity:Mtls:DeploymentMode"] = "TrustedProxy",
            });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ((IAsyncLifetime)factory).InitializeAsync());

        Assert.Contains("TrustedProxyNetworks", exception.ToString(),
            StringComparison.Ordinal);
    }

    private static MtlsClientCertificatePolicy CreatePolicy(
        X509Certificate2 certificate,
        MtlsRevocationFailureMode failureMode,
        X509ChainStatusFlags flags)
    {
        var thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        return new MtlsClientCertificatePolicy(
            new MtlsOptions
            {
                Enabled = true,
                DeploymentMode = MtlsDeploymentMode.DirectTls,
                RequireValidCertificateChain = true,
                RevocationMode = MtlsCertificateRevocationMode.Online,
                RevocationFailureMode = failureMode,
                ClientCertificateThumbprints = new Dictionary<string, HashSet<string>>
                {
                    ["bound-client"] = new(StringComparer.Ordinal) { thumbprint },
                },
            },
            new StubChainValidator(new(false, flags)));
    }

    private static DefaultHttpContext ContextWith(
        X509Certificate2 certificate)
    {
        var context = new DefaultHttpContext();
        context.Connection.ClientCertificate = certificate;
        return context;
    }

    private static X509Certificate2 CreateCertificate() => CreateCertificate(
        DateTimeOffset.UtcNow.AddMinutes(-1),
        DateTimeOffset.UtcNow.AddHours(1));

    private static X509Certificate2 CreateCertificate(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=mtls-policy-test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    private sealed class StubChainValidator(MtlsCertificateChainResult result)
        : IMtlsCertificateChainValidator
    {
        public MtlsCertificateChainResult Validate(
            X509Certificate2 certificate,
            MtlsCertificateRevocationMode revocationMode,
            TimeSpan timeout) => result;
    }
}
