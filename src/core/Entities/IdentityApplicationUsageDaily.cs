namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Daily count of application uses per node and dimension, the user being one
/// of the dimensions. Each node only ever writes its own rows, so the cluster
/// never contends on a counter; the Management overview sums nodes and users.
/// The single source for usage metrics, per application and per user.
/// </summary>
public sealed class IdentityApplicationUsageDaily
{
    public long Id { get; set; }

    /// <summary>UTC day (time part zero).</summary>
    public DateTime Day { get; set; }

    /// <summary>Node that counted the uses; <c>legacy</c> for history migrated from per-event rows.</summary>
    public string Node { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string EndpointType { get; set; } = string.Empty;

    /// <summary>Empty when the request named no grant type (a unique key cannot hold NULLs).</summary>
    public string GrantType { get; set; } = string.Empty;

    public string Outcome { get; set; } = "succeeded";

    /// <summary>
    /// The user the use was for; empty when there is none (client credentials,
    /// failed requests). Personal data: read with the users capability.
    /// </summary>
    public string UserId { get; set; } = string.Empty;
    public long Count { get; set; }
    public DateTime LastOccurredAtUtc { get; set; }
}
