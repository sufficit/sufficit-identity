namespace Sufficit.Identity.Vault;

/// <summary>
/// Transit-style encryption-as-a-service. Keys never leave the vault boundary;
/// callers only see self-describing ciphertext. When
/// <see cref="VaultOptions.Enabled"/> is false, resolves to
/// <see cref="PassThroughKeyVault"/> (round-trip without crypto).
/// </summary>
public interface IKeyVault
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> under a named, versioned key.
    /// Returns self-describing ciphertext that embeds the key name + version,
    /// so <see cref="DecryptAsync"/> needs no side table.
    /// </summary>
    /// <param name="keyName">A stable key name, e.g. <c>ssf-stream-authz</c>.</param>
    /// <param name="plaintext">The UTF-8 bytes to encrypt.</param>
    /// <param name="additionalAuthenticatedData">Optional AAD bound to the
    /// ciphertext (e.g. <c>{ "stream_id": streamId }</c>). Must be supplied
    /// again on decrypt; a mismatch fails fast.</param>
    Task<string> EncryptAsync(
        string keyName,
        byte[] plaintext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Encrypts a UTF-8 string (convenience over the byte-span overload).
    /// </summary>
    async Task<string> EncryptAsync(
        string keyName,
        string plaintext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
        => await EncryptAsync(
            keyName,
            System.Text.Encoding.UTF8.GetBytes(plaintext),
            additionalAuthenticatedData,
            cancellationToken);

    /// <summary>
    /// Decrypts self-describing ciphertext. The embedded key id selects the
    /// key version. Returns the original plaintext bytes.
    /// </summary>
    Task<ReadOnlyMemory<byte>> DecryptAsync(
        string ciphertext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts to a UTF-8 string (convenience over the byte-memory overload).
    /// </summary>
    async Task<string> DecryptStringAsync(
        string ciphertext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
        => System.Text.Encoding.UTF8.GetString(
            (await DecryptAsync(ciphertext, additionalAuthenticatedData, cancellationToken)).ToArray());

    /// <summary>
    /// Creates a new key version for <paramref name="keyName"/>. New encrypts
    /// use it; old ciphertext still decrypts (version embedded in the blob).
    /// </summary>
    Task<KeyId> RotateKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Parsed identity of a vault key: its name + version. Embedded in every
/// ciphertext blob so decrypt picks the right key version for free.
/// </summary>
public sealed record KeyId(string Name, int Version);
