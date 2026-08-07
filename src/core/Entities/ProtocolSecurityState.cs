namespace Sufficit.Identity.Core.Entities;

public sealed class DpopReplayEntry
{
    public string Key { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}

public sealed class CibaPendingState
{
    public string AuthReqId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string ScopesJson { get; set; } = "[]";
    public string? BindingMessage { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime LastPollAtUtc { get; set; }
    public string? ApprovedSubject { get; set; }
    public string State { get; set; } = "pending";
    public string? ConsumptionId { get; set; }
}
