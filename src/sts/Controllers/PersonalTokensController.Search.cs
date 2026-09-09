using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;

namespace Sufficit.Identity.STS.Controllers;

public sealed partial class PersonalTokensController
{
    /// <summary>Bounded self-service listing. Never materializes OAuth payloads or reference secrets.</summary>
    [HttpGet("search")]
    public async Task<ActionResult<PersonalTokenPage>> Search(
        [FromQuery] int offset = 0, [FromQuery] int pageSize = 25,
        [FromQuery] string state = "active", [FromQuery] string? search = null,
        CancellationToken cancellationToken = default)
    {
        if (offset < 0 || offset > int.MaxValue - PersonalTokenSearch.ScanLimit || pageSize is < 1 or > 100 || search?.Length > 200
            || state is not ("active" or "history" or "legacy" or "all"))
            return BadRequest(new { error = "invalid_token_query" });

        return Ok(await PersonalTokenSearch.ReadAsync(_database, RequireSubject(),
            offset, pageSize, state, search, cancellationToken));
    }

    /// <summary>Read-only selection for bounded cleanup previews; ownership is always enforced.</summary>
    [HttpPost("lookup")]
    public async Task<ActionResult<IReadOnlyList<PersonalTokenSummary>>> Lookup(
        [FromBody] string[] ids, CancellationToken cancellationToken)
    {
        if (ids.Length > 100 || ids.Any(id => string.IsNullOrWhiteSpace(id) || id.Length > 200))
            return BadRequest(new { error = "invalid_token_selection" });
        var page = await PersonalTokenSearch.ReadAsync(_database, RequireSubject(), 0, 100, "all", null, cancellationToken, ids);
        return Ok(page.Items);
    }
}

public sealed record PersonalTokenPage(IReadOnlyList<PersonalTokenSummary> Items, int? NextOffset, string SubjectId);

/// <summary>
/// Bounded metadata scanning keeps the JSON-property rules provider-independent.
/// Continuation is an offset in the owner's ordered metadata, never an owner ID.
/// Empty pages may have a continuation when the scan budget was reached.
/// No fallback to the unbounded legacy endpoint: deploy Identity before the UI.
/// </summary>
public static class PersonalTokenSearch
{
    public const int ScanLimit = 2000;
    private const string Prefix = "urn:sufficit:token:";
    private const string PersonalClient = "SufficitAPIUserAccess";
    private const string AccessType = OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.AccessToken;

    public static async Task<PersonalTokenPage> ReadAsync(AppDbContext db, string subject,
        int offset, int pageSize, string state, string? search, CancellationToken ct, string[]? ids = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var query = db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
            .Where(t => t.Subject == subject && t.ReferenceId != null
                && (t.Type == AccessType || t.Type == "legacy_reference_token"));
        var result = new List<PersonalTokenSummary>();
        var owned = query;
        var now = DateTime.UtcNow;
        if (ids is not null) query = query.Where(t => ids.Contains(t.Id!));
        if (state == "active") query = query.Where(t => t.Type == AccessType && t.Status == "valid"
            && t.RedemptionDate == null && (t.ExpirationDate == null || t.ExpirationDate > now));
        if (state == "legacy") query = query.Where(t => t.Type == "legacy_reference_token");
        if (state == "history") query = query.Where(t => t.Type == "legacy_reference_token" || t.Status != "valid"
            || t.RedemptionDate != null || t.ExpirationDate <= now);
        var scanned = 0;
        var term = search?.Trim() ?? "";
        while (scanned < ScanLimit)
        {
            // Projection is essential: a tracked OpenIddict entity also loads
            // Payload, which can be much larger than the visible metadata.
            var batch = await query.OrderByDescending(t => t.CreationDate).ThenBy(t => t.Id)
                .Skip(offset).Take(200)
                .Select(t => new { t.Id, t.Type, t.Status, t.CreationDate,
                    t.ExpirationDate, t.RedemptionDate, t.Properties,
                    Client = t.Application == null ? null : t.Application.ClientId })
                .ToListAsync(ct);
            if (batch.Count == 0) return new(result, null, subject);
            foreach (var row in batch)
            {
                ct.ThrowIfCancellationRequested();
                using var json = JsonDocument.Parse(row.Properties ?? "{}");
                string? Property(string name) => json.RootElement.TryGetProperty(Prefix + name, out var value)
                    && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                var legacy = row.Type == "legacy_reference_token";
                var client = Property("client_id") ?? row.Client;
                var archived = !string.IsNullOrWhiteSpace(Property("archived_at"));
                var active = !legacy && row.Status == "valid" && row.RedemptionDate == null
                    && (row.ExpirationDate == null || row.ExpirationDate > now);
                var description = Property("description");
                var match = !archived && (legacy || client == PersonalClient)
                    && (state == "all" || state == "legacy" && legacy
                        || state == "active" && active || state == "history" && !active)
                    && (term.Length == 0 || (description?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                        || (row.Id?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false));
                if (match && legacy)
                {
                    // Only inspect replacement metadata for this candidate,
                    // and compare the parsed property, not an arbitrary substring.
                    var candidates = owned.Where(t => t.Type == AccessType && t.Properties != null
                        && t.Properties.Contains(Prefix + "replaces_id") && t.Properties.Contains(row.Id!))
                        .Select(t => t.Properties).AsAsyncEnumerable();
                    await foreach (var candidate in candidates.WithCancellation(ct))
                    {
                        using var replacement = JsonDocument.Parse(candidate!);
                        if (replacement.RootElement.TryGetProperty(Prefix + "replaces_id", out var id)
                            && id.ValueKind == JsonValueKind.String && id.GetString() == row.Id)
                        { match = false; break; }
                    }
                }
                if (match && result.Count == pageSize)
                    return new(result, offset, subject); // lookahead stays on the next page
                offset = checked(offset + 1);
                scanned++;
                if (match)
                    // The wire contract keeps the UI's short type name; the
                    // database uses OpenIddict's RFC URN, not "access_token".
                    result.Add(new(row.Id!, legacy ? "legacy_reference_token" : "access_token", Guid.TryParse(subject, out var owner) ? owner : null,
                        client ?? PersonalClient, AsOffset(row.CreationDate) ?? DateTimeOffset.MinValue,
                        AsOffset(row.ExpirationDate), AsOffset(row.RedemptionDate), description, null, row.Status ?? "unknown"));
            }
            if (batch.Count < 200) return new(result, null, subject);
        }
        return new(result, offset, subject);
    }

    private static DateTimeOffset? AsOffset(DateTime? value) => value.HasValue
        ? new DateTimeOffset(DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)) : null;
}
