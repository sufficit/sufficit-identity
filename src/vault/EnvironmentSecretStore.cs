namespace Sufficit.Identity.Vault;

/// <summary>
/// Zero-dependency secret source used by default. Environment variables are
/// the only source for deployment secrets, so they never need to be copied
/// into appsettings files. A logical name such as
/// <c>database/password</c> maps to
/// <c>SUFFICIT_SECRET_DATABASE_PASSWORD</c> (case-insensitive).
/// </summary>
public sealed class EnvironmentSecretStore : ISecretStore
{
    private const string Prefix = "SUFFICIT_SECRET_";

    internal static string EnvironmentVariableName(string name) =>
        Prefix + new string(name
            .Select(character => char.IsLetterOrDigit(character)
                ? char.ToUpperInvariant(character)
                : '_')
            .ToArray());

    public Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        cancellationToken.ThrowIfCancellationRequested();

        var environmentName = EnvironmentVariableName(name);

        var value = Environment.GetEnvironmentVariable(environmentName);
        return Task.FromResult(
            string.IsNullOrWhiteSpace(value) ? null : value);
    }
}
