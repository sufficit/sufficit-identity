using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DatabaseTransportPolicyTests
{
    [Fact]
    public void Verified_tls_requires_certificate_validation_mode()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            DatabaseTransportPolicy.Validate(
                "Server=db;Database=identity;User Id=identity;Password=secret;SslMode=Preferred",
                DatabaseTransportMode.RequireVerifiedTls,
                isDevelopment: false));

        Assert.Contains("VerifyCA or VerifyFull", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Private_socket_requires_an_explicit_socket_path()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            DatabaseTransportPolicy.Validate(
                "Server=localhost;Database=identity;User Id=identity;Password=secret",
                DatabaseTransportMode.PrivateSocket,
                isDevelopment: false));

        Assert.Contains("UnixSocket", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Verified_tls_accepts_an_explicit_ca()
    {
        var caPath = Path.GetTempFileName();
        try
        {
            DatabaseTransportPolicy.Validate(
                $"Server=db;Database=identity;User Id=identity;Password=secret;SslMode=VerifyCA;SslCa={caPath}",
                DatabaseTransportMode.RequireVerifiedTls,
                isDevelopment: false);
        }
        finally
        {
            File.Delete(caPath);
        }
    }
}
