using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Who a <c>subject_token</c> stands for: a user, or the client the token was
/// issued to. <see cref="Rejection"/> is set when it stands for neither.
/// </summary>
public sealed record SubjectTokenResolution(
    ApplicationUser? User,
    object? Application,
    string? ClientId,
    string? Rejection)
{
    public static SubjectTokenResolution ForUser(ApplicationUser user) =>
        new(user, null, null, null);

    public static SubjectTokenResolution ForClient(object application, string clientId) =>
        new(null, application, clientId, null);

    public static SubjectTokenResolution Rejected(string rejection) =>
        new(null, null, null, rejection);

    public bool IsRejected => Rejection is not null;
}

/// <summary>
/// Resolves the party a token exchange is performed on behalf of (RFC 8693
/// section 2.1). Two shapes are accepted, and the difference matters: a user
/// subject produces a user identity, while a client subject produces a client
/// identity with no user behind it.
/// </summary>
public interface ISubjectTokenResolver
{
    Task<SubjectTokenResolution> ResolveAsync(
        ClaimsPrincipal subjectToken,
        string? authorizedParty,
        CancellationToken cancellationToken = default);
}

internal sealed class SubjectTokenResolver(
    UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn,
    IOpenIddictApplicationManager applications,
    TokenExchangeOptions options)
    : ISubjectTokenResolver
{
    public async Task<SubjectTokenResolution> ResolveAsync(
        ClaimsPrincipal subjectToken,
        string? authorizedParty,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subjectToken);

        var subject = subjectToken.GetClaim(Claims.Subject);
        var user = subject is not null
            ? await users.FindByIdAsync(subject)
            : null;

        if (user is not null)
        {
            return await signIn.CanSignInAsync(user)
                ? SubjectTokenResolution.ForUser(user)
                : SubjectTokenResolution.Rejected(
                    "The subject_token no longer identifies a user that is allowed to sign in.");
        }

        if (!options.AllowClientSubjectTokens)
        {
            return SubjectTokenResolution.Rejected(
                "The subject_token no longer identifies a user that is allowed to sign in.");
        }

        // A subject token without a user qualifies only as the client's own
        // token: its subject is its single authorized party. A token a client
        // merely received from another client has a different subject and
        // party, and provenance already bound the party to this caller.
        var application = subject is not null
            && string.Equals(subject, authorizedParty, StringComparison.Ordinal)
                ? await applications.FindByClientIdAsync(subject, cancellationToken)
                : null;

        return application is null
            ? SubjectTokenResolution.Rejected(
                "The subject_token does not identify a user or the client it was issued to.")
            : SubjectTokenResolution.ForClient(application, subject!);
    }
}
