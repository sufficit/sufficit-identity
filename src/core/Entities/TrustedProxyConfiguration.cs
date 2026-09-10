namespace Sufficit.Identity.Core.Entities;

/// <summary>Database additions to the file-managed proxy trust boundary.</summary>
public sealed class TrustedProxyConfiguration
{
    public int Id { get; set; } = 1;
    public string NetworksJson { get; set; } = "[]";
    public int? ForwardLimit { get; set; }
    public string Revision { get; set; } = "initial";
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UnixEpoch;
}
