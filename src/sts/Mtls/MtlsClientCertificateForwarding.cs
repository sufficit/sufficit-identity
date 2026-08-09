using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS.Mtls;

public static class MtlsClientCertificateForwardingExtensions
{
    /// <summary>
    /// Projects a proxy-validated certificate onto the connection only when
    /// the immediate peer belongs to the dedicated mTLS proxy allow-list.
    /// This must run before UseForwardedHeaders changes RemoteIpAddress.
    /// </summary>
    public static IApplicationBuilder UseMtlsClientCertificateForwarding(
        this IApplicationBuilder application,
        MtlsOptions options)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(options);
        if (!options.Enabled)
        {
            return application;
        }
        var networks = MtlsClientCertificateForwarding.ParseNetworks(
            options.TrustedProxyNetworks);
        var logger = application.ApplicationServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("Sufficit.Identity.STS.Mtls.CertificateForwarding");
        return application.Use((context, next) =>
            MtlsClientCertificateForwarding.InvokeAsync(
                context,
                next,
                options,
                networks,
                logger));
    }
}

internal static class MtlsClientCertificateForwarding
{
    internal const int MaximumHeaderLength = 32_768;

    internal static IReadOnlyList<IPNetwork> ParseNetworks(
        IEnumerable<string> values)
    {
        var result = new List<IPNetwork>();
        foreach (var value in values)
        {
            var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
            if (!IPAddress.TryParse(parts[0], out var prefix))
            {
                throw new InvalidOperationException(
                    $"Invalid mTLS trusted proxy network '{value}'.");
            }
            var prefixLength = parts.Length == 2
                && int.TryParse(parts[1], out var parsed)
                ? parsed
                : prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    ? 32
                    : 128;
            var maximum = prefix.AddressFamily ==
                System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            if (prefixLength is < 1 || prefixLength > maximum)
            {
                throw new InvalidOperationException(
                    $"Invalid mTLS trusted proxy network '{value}'. Catch-all networks are forbidden.");
            }
            try
            {
                result.Add(new IPNetwork(prefix, prefixLength));
            }
            catch (ArgumentException exception)
            {
                throw new InvalidOperationException(
                    $"Invalid mTLS trusted proxy network '{value}'.",
                    exception);
            }
        }
        return result;
    }

    internal static async Task InvokeAsync(
        HttpContext context,
        Func<Task> next,
        MtlsOptions options,
        IReadOnlyList<IPNetwork> trustedNetworks,
        ILogger logger)
    {
        var headerName = options.ForwardedCertificateHeader;
        context.Request.Headers.TryGetValue(headerName, out var values);
        context.Request.Headers.Remove(headerName);

        if (!options.Enabled
            || options.DeploymentMode != MtlsDeploymentMode.TrustedProxy)
        {
            await next();
            return;
        }

        // In proxy mode, a certificate observed on any other path is outside
        // the attested trust topology and cannot be reused as client proof.
        context.Connection.ClientCertificate = null;
        var remoteAddress = context.Connection.RemoteIpAddress;
        var trusted = remoteAddress is not null
            && trustedNetworks.Any(network => network.Contains(remoteAddress));
        if (!trusted)
        {
            if (values.Count > 0)
            {
                logger.LogWarning(
                    "Discarded a forwarded mTLS certificate from an untrusted immediate peer. RemoteIpAddress={RemoteIpAddress}",
                    remoteAddress);
            }
            await next();
            return;
        }

        if (values.Count == 0)
        {
            await next();
            return;
        }
        if (values.Count != 1
            || string.IsNullOrWhiteSpace(values[0])
            || values[0]!.Length > MaximumHeaderLength)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        try
        {
            var rawValue = values[0]!;
            // Base64 DER legitimately contains '+', which form-style URL
            // decoding would turn into a space. Decode only an actually
            // percent-encoded proxy value (the common PEM forwarding form).
            var value = rawValue.Contains('%')
                ? WebUtility.UrlDecode(rawValue)
                : rawValue;
            X509Certificate2 certificate;
            if (value.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                certificate = X509Certificate2.CreateFromPem(value);
            }
            else
            {
                certificate = X509CertificateLoader.LoadCertificate(
                    Convert.FromBase64String(value));
            }
            context.Connection.ClientCertificate = certificate;
            context.Response.RegisterForDispose(certificate);
        }
        catch (Exception exception) when (
            exception is FormatException
                or CryptographicException
                or ArgumentException)
        {
            logger.LogWarning(
                "Rejected malformed forwarded mTLS certificate from a trusted proxy. RemoteIpAddress={RemoteIpAddress}",
                remoteAddress);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        await next();
    }
}
