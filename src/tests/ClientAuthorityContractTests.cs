using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Clients only authenticate. Authority comes from users, and software acts
/// as a system user (SystemUserClientBinding). Roles declared on a client
/// registration were a second authority model and are gone; if any production
/// path read them again, a client property would once more grant management
/// capabilities on its own. This is the stop.
/// </summary>
public sealed class ClientAuthorityContractTests
{
    private const string RetiredProperty = "identity:client:roles";

    [Fact]
    public void No_production_path_reads_roles_from_a_client()
    {
        var root = ResolveIdentityRepository();
        var offenders = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
                || path.EndsWith(".razor", StringComparison.Ordinal)
                || path.EndsWith(".json", StringComparison.Ordinal))
            .Where(path => !IsExcluded(Path.GetRelativePath(root, path)))
            .Where(path => File.ReadAllText(path).Contains(RetiredProperty, StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(root, path))
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "Client roles are retired; bind the client to a system user instead: "
            + string.Join(", ", offenders));
    }

    private static bool IsExcluded(string relative)
    {
        var parts = relative.Split(Path.DirectorySeparatorChar);
        return parts.Contains("obj") || parts.Contains("bin") || parts.Contains("tests")
            || parts.Contains("Migrations");
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }
}
