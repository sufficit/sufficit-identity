using System.Text.Json;

namespace Sufficit.Identity.Server;

internal sealed record TokenPruningState(DateTimeOffset LastSuccessUtc, long Tokens, long Authorizations)
{
    internal static async Task<TokenPruningState> RunAsync(string path,
        Func<CancellationToken, Task<(long Tokens, long Authorizations)>> prune,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Local/shared-volume lock only; not a distributed lock between database replicas.
        await using var lease = new FileStream(path + ".lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        var result = await prune(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var state = new TokenPruningState(DateTimeOffset.UtcNow, result.Tokens, result.Authorizations);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(state), cancellationToken);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
        return state;
    }

    internal static async Task<TokenPruningState> ReadFreshAsync(
        string path, DateTimeOffset now, TimeSpan maximumAge)
    {
        var state = JsonSerializer.Deserialize<TokenPruningState>(await File.ReadAllTextAsync(path))
            ?? throw new InvalidDataException("Missing pruning status.");
        if (state.LastSuccessUtc > now.AddMinutes(5) || now - state.LastSuccessUtc > maximumAge)
            throw new InvalidDataException("Pruning success is overdue or its timestamp is invalid.");
        return state;
    }
}
