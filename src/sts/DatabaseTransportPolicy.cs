using MySqlConnector;

namespace Sufficit.Identity.STS;

public static class DatabaseTransportPolicy
{
    public static void Validate(
        string connectionString,
        DatabaseTransportMode mode,
        bool isDevelopment)
    {
        if (string.Equals(connectionString, "unused", StringComparison.Ordinal))
        {
            return;
        }

        var builder = new MySqlConnectionStringBuilder(connectionString);
        switch (mode)
        {
            case DatabaseTransportMode.RequireVerifiedTls:
                if (builder.SslMode is not (MySqlSslMode.VerifyCA or MySqlSslMode.VerifyFull))
                {
                    throw new InvalidOperationException(
                        "Database:TransportMode=RequireVerifiedTls requires " +
                        "MySqlConnector SslMode=VerifyCA or VerifyFull.");
                }

                if (builder.SslMode == MySqlSslMode.VerifyCA &&
                    string.IsNullOrWhiteSpace(builder.SslCa))
                {
                    throw new InvalidOperationException(
                        "Database:TransportMode=RequireVerifiedTls with SslMode=VerifyCA " +
                        "requires an explicit SslCa path.");
                }
                if (builder.SslMode == MySqlSslMode.VerifyCA &&
                    !File.Exists(builder.SslCa))
                {
                    throw new InvalidOperationException(
                        $"Database TLS CA file '{builder.SslCa}' does not exist.");
                }
                break;

            case DatabaseTransportMode.PrivateSocket:
                var unixSocket = builder.ContainsKey("Unix Socket")
                    ? builder["Unix Socket"]?.ToString()
                    : builder.ContainsKey("UnixSocket")
                        ? builder["UnixSocket"]?.ToString()
                        : null;
                if (string.IsNullOrWhiteSpace(unixSocket))
                {
                    throw new InvalidOperationException(
                        "Database:TransportMode=PrivateSocket requires an explicit UnixSocket path.");
                }
                break;

            case DatabaseTransportMode.Compatibility when !isDevelopment:
                // Compatibility is intentionally observable rather than
                // silently presented as a verified production transport. The
                // operator can move to one of the explicit modes per rollout.
                break;
        }
    }
}
