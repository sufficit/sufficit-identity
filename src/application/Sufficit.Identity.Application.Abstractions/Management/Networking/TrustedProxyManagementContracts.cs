using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Networking;

public interface ITrustedProxyManagementService
{
    Task<ManagementTrustedProxies> GetAsync(ManagementRequestContext context, CancellationToken cancellationToken = default);
    Task<ManagementTrustedProxies> SaveAsync(SaveTrustedProxies command, ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementTrustedProxies(IReadOnlyList<string> FileNetworks,
    IReadOnlyList<string> DatabaseNetworks, IReadOnlyList<string> EffectiveNetworks,
    int FileForwardLimit, int? DatabaseForwardLimit, int ForwardLimit, string Revision,
    DateTime? UpdatedAtUtc, int RefreshSeconds, bool NotificationsEnabled = false,
    bool NotificationsConnected = false, bool NotificationPending = false,
    DateTimeOffset? LastConfirmedAtUtc = null, long Generation = 0, bool IsFresh = true);

public sealed record SaveTrustedProxies(string[] Networks, int? ForwardLimit, string Revision);
