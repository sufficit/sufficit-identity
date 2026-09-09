using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Controllers;

public sealed partial class PersonalTokensController
{
    /// <summary>
    /// Removes an expired/revoked personal token from the self-service list,
    /// retaining its metadata and legacy identifier for audit. Never revokes
    /// a currently valid token as a side effect of a cleanup request.
    /// </summary>
    [HttpPost("{id}/archive")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Archive(string id, CancellationToken cancellationToken)
    {
        var token = await _tokenManager.FindByIdAsync(id, cancellationToken);
        if (token is null
            || !string.Equals(await _tokenManager.GetSubjectAsync(token, cancellationToken),
                RequireSubject(), StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(await _tokenManager.GetReferenceIdAsync(token, cancellationToken)))
            return NotFound();

        var type = await _tokenManager.GetTypeAsync(token, cancellationToken);
        if (type != TokenTypeIdentifiers.AccessToken && type != LegacyReferenceTokenType)
            return NotFound();

        if (await IsArchivedAsync(token, cancellationToken))
            return NoContent();

        var descriptor = new OpenIddictTokenDescriptor();
        await _tokenManager.PopulateAsync(descriptor, token, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (descriptor.Status != Statuses.Revoked
            && descriptor.Status != Statuses.Redeemed
            && !(descriptor.ExpirationDate is { } expiration && expiration <= now))
            return Conflict(new { error = "Only expired, revoked or redeemed personal tokens can be archived." });

        // One concurrency-checked update: if another request renewed the token,
        // don't revoke that new state. Archived credentials can never be reused.
        descriptor.Status = Statuses.Revoked;
        descriptor.Properties[ArchivedAtProperty] = JsonSerializer.SerializeToElement(now);
        try
        {
            await _tokenManager.UpdateAsync(token, descriptor, cancellationToken);
            await PersistPropertiesAsync(token, descriptor.Properties, cancellationToken);
        }
        catch (OpenIddictExceptions.ConcurrencyException)
        {
            return Conflict(new { error = "The token changed. Refresh the list before trying again." });
        }

        return NoContent();
    }

    private async Task<bool> IsArchivedAsync(object token, CancellationToken cancellationToken)
        => (await _tokenManager.GetPropertiesAsync(token, cancellationToken)).ContainsKey(ArchivedAtProperty);
}
