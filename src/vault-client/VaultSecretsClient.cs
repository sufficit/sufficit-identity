using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Vault.Client;

/// <summary>
/// Remote named-secret access backed by the identity management API. The
/// server keeps every cryptographic responsibility; this client only moves
/// plaintext over the already-authenticated HTTPS channel.
/// </summary>
public interface IVaultSecretsClient
{
    Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string? contextId = null,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret?> GetAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default);

    /// <summary>Null when the secret does not exist. An expired secret is
    /// returned with <see cref="VaultSecretStatus.Expired"/> and a null
    /// value (the server answers 410 and never discloses expired material).</summary>
    Task<ResolvedManagementVaultSecret?> ResolveAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret> PutAsync(
        string name,
        string value,
        DateTime? expiresAtUtc = null,
        string? contextId = null,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default);
}

public sealed class VaultSecretsClient(
    IHttpClientFactory httpFactory,
    IOptions<VaultSecretsClientOptions> options,
    IMemoryCache cache,
    ILogger<VaultSecretsClient> logger) : IVaultSecretsClient
{
    // Safe to hold in singletons: every call rents a client from the factory,
    // so handler rotation (DNS, connection recycling) keeps working.
    internal const string HttpClientName = "Sufficit.Identity.Vault.Client";

    private HttpClient Http => httpFactory.CreateClient(HttpClientName);
    private const string CachePrefix = "sufficit:vault-client:resolve:";
    private const string StalePrefix = "sufficit:vault-client:stale:";

    private static readonly JsonSerializerOptions Json = new(
        JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public async Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string? contextId = null,
        CancellationToken cancellationToken = default)
    {
        var response = await Http.GetAsync(
            $"api/vault/secrets?contextId={Context(contextId)}",
            cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<
                IReadOnlyList<ManagementVaultSecret>>(Json, cancellationToken)
            ?? [];
    }

    public async Task<ManagementVaultSecret?> GetAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default)
    {
        var response = await Http.GetAsync(
            $"api/vault/secrets/{Uri.EscapeDataString(name).Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)}?contextId={Context(contextId)}",
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ManagementVaultSecret>(
            Json, cancellationToken);
    }

    public async Task<ResolvedManagementVaultSecret?> ResolveAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default)
    {
        var context = Context(contextId);
        var cacheKey = CachePrefix + context + "\n" + name;
        if (cache.TryGetValue<ResolvedManagementVaultSecret>(
                cacheKey, out var cached) && cached is not null)
        {
            return cached;
        }

        HttpResponseMessage response;
        try
        {
            response = await Http.GetAsync(
                $"api/vault/secrets/resolve?name={Uri.EscapeDataString(name)}&contextId={context}",
                cancellationToken);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or TaskCanceledException
            && !cancellationToken.IsCancellationRequested)
        {
            return ServeStaleOrThrow(cacheKey, name, exception);
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NotFound) return null;
            if (response.StatusCode == HttpStatusCode.Gone)
            {
                // Expired: metadata travels in the body, the value never does.
                return await response.Content
                    .ReadFromJsonAsync<ResolvedManagementVaultSecret>(
                        Json, cancellationToken);
            }

            if (response.StatusCode is HttpStatusCode.InternalServerError
                or HttpStatusCode.BadGateway
                or HttpStatusCode.ServiceUnavailable
                or HttpStatusCode.GatewayTimeout)
            {
                return ServeStaleOrThrow(
                    cacheKey,
                    name,
                    new HttpRequestException(
                        $"Vault resolve failed with {(int)response.StatusCode}."));
            }

            response.EnsureSuccessStatusCode();
            var resolved = await response.Content
                .ReadFromJsonAsync<ResolvedManagementVaultSecret>(
                    Json, cancellationToken)
                ?? throw new InvalidOperationException(
                    "Vault resolve returned an empty body.");

            CacheResolution(cacheKey, resolved);
            return resolved;
        }
    }

    public async Task<ManagementVaultSecret> PutAsync(
        string name,
        string value,
        DateTime? expiresAtUtc = null,
        string? contextId = null,
        CancellationToken cancellationToken = default)
    {
        var context = Context(contextId);
        var response = await Http.PutAsJsonAsync(
            $"api/vault/secrets/{Uri.EscapeDataString(name).Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)}?contextId={context}",
            new SaveManagementVaultSecret(value, expiresAtUtc),
            Json,
            cancellationToken);
        response.EnsureSuccessStatusCode();
        Invalidate(name, context);
        return await response.Content.ReadFromJsonAsync<ManagementVaultSecret>(
                Json, cancellationToken)
            ?? throw new InvalidOperationException(
                "Vault put returned an empty body.");
    }

    public async Task<bool> DeleteAsync(
        string name,
        string? contextId = null,
        CancellationToken cancellationToken = default)
    {
        var context = Context(contextId);
        var response = await Http.DeleteAsync(
            $"api/vault/secrets/{Uri.EscapeDataString(name).Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)}?contextId={context}",
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return false;
        response.EnsureSuccessStatusCode();
        Invalidate(name, context);
        return true;
    }

    private void CacheResolution(
        string cacheKey,
        ResolvedManagementVaultSecret resolved)
    {
        if (resolved.Status == VaultSecretStatus.Expired) return;

        var ttl = TimeSpan.FromSeconds(
            Math.Max(1, options.Value.ResolveCacheSeconds));
        if (resolved.ExpiresAtUtc is { } expiresAtUtc)
        {
            var untilExpiry = expiresAtUtc - DateTime.UtcNow;
            if (untilExpiry <= TimeSpan.Zero) return;
            if (untilExpiry < ttl) ttl = untilExpiry;
        }

        cache.Set(cacheKey, resolved, ttl);
        if (options.Value.StaleFallbackHours > 0)
        {
            cache.Set(
                StalePrefix + cacheKey,
                resolved,
                TimeSpan.FromHours(options.Value.StaleFallbackHours));
        }
    }

    private ResolvedManagementVaultSecret ServeStaleOrThrow(
        string cacheKey,
        string name,
        Exception exception)
    {
        if (options.Value.StaleFallbackHours > 0
            && cache.TryGetValue<ResolvedManagementVaultSecret>(
                StalePrefix + cacheKey, out var stale)
            && stale is not null
            && (stale.ExpiresAtUtc is not { } expiresAtUtc
                || expiresAtUtc > DateTime.UtcNow))
        {
            logger.LogWarning(
                exception,
                "Vault unreachable; serving last known value for {SecretName}.",
                name);
            return stale;
        }

        throw exception;
    }

    private void Invalidate(string name, string context)
    {
        var cacheKey = CachePrefix + context + "\n" + name;
        cache.Remove(cacheKey);
        cache.Remove(StalePrefix + cacheKey);
    }

    private string Context(string? contextId) =>
        Uri.EscapeDataString(
            string.IsNullOrWhiteSpace(contextId)
                ? options.Value.ContextId
                : contextId);
}
