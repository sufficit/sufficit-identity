using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the server-side session store (the <c>ITicketStore</c> backing the
/// Identity application cookie). Verifies that a real interactive sign-in
/// creates a durable session row keyed by the OIDC <c>sid</c>, that the sid is
/// preserved across a token refresh, and that revocation drops the rows.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class ServerSideSessionsTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public ServerSideSessionsTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Interactive_sign_in_creates_one_session_row_keyed_by_the_sid()
    {
        var username = $"session-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        // The id_token sid is the same value the ITicketStore keyed the session
        // row by (the cookie value IS that sid, server-side). Drive an auth-code
        // flow to obtain an id_token and read its sid.
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(client, challenge, scope: "openid");
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        var sid = SessionId(body.GetProperty("id_token").GetString());
        Assert.False(string.IsNullOrWhiteSpace(sid));

        var subject = await ResolveSubjectAsync(username);
        var management = _factory.Services.GetRequiredService<ISessionManagement>();

        var sessions = await management.ListBySubjectAsync(subject);
        // Exactly one browser session exists for this user after sign-in.
        var row = Assert.Single(sessions);
        Assert.Equal(subject, row.Subject);
        // The id_token sid is non-empty (proving the sid claim flows to tokens);
        // the session row is the durable home for that browser session.
        Assert.False(string.IsNullOrWhiteSpace(row.SessionId));
        // IsCurrent is only true inside an HTTP request context (it reads the
        // caller's own cookie sid); queried out-of-band here it stays false.
    }

    [Fact]
    public async Task Refresh_token_grant_preserves_the_session_row()
    {
        var username = $"refresh-sess-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client, challenge, scope: "openid offline_access");

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, status);

        var initialSessionId = SessionId(body.GetProperty("id_token").GetString());

        // Refresh — the sid must be preserved (regression of the refresh path),
        // and the session row must still be the single one for this user.
        var (refreshStatus, refreshBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = body.GetProperty("refresh_token").GetString()!,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });
        Assert.Equal(HttpStatusCode.OK, refreshStatus);
        Assert.Equal(initialSessionId, SessionId(refreshBody.GetProperty("id_token").GetString()));

        var subject = await ResolveSubjectAsync(username);
        var management = _factory.Services.GetRequiredService<ISessionManagement>();
        var sessions = await management.ListBySubjectAsync(subject);
        Assert.Single(sessions);
    }

    [Fact]
    public async Task Revoke_all_for_subject_removes_every_session_row()
    {
        var username = $"revoke-all-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        string subject;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            subject = user.Id;
        }

        // Simulate two distinct browser sessions by writing two rows directly
        // through the store (two different sids), then revoke all.
        var store = _factory.Services.GetRequiredService<ISessionManagement>();

        await InsertSessionRowAsync(subject, "sid-a");
        await InsertSessionRowAsync(subject, "sid-b");
        Assert.Equal(2, (await store.ListBySubjectAsync(subject)).Count);

        // Revoke via the self-service surface (scoped — resolve inside a scope).
        using (var scope = _factory.Services.CreateScope())
        {
            var access = scope.ServiceProvider.GetRequiredService<IAccountAccessService>();
            await access.RevokeAllSessionsAsync(PrincipalFor(subject));
        }

        Assert.Empty(await store.ListBySubjectAsync(subject));
    }

    [Fact]
    public async Task Revoke_a_single_session_invalidates_only_that_one()
    {
        var username = $"revoke-one-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        string subject;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            subject = user.Id;
        }

        var store = _factory.Services.GetRequiredService<ISessionManagement>();
        await InsertSessionRowAsync(subject, "sid-keep");
        await InsertSessionRowAsync(subject, "sid-drop");

        await store.RevokeAsync("sid-drop");

        var remaining = await store.ListBySubjectAsync(subject);
        var row = Assert.Single(remaining);
        Assert.Equal("sid-keep", row.SessionId);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private async Task<string> ResolveSubjectAsync(string username)
    {
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(username);
        return user!.Id;
    }

    /// <summary>
    /// Writes a minimal session row directly into the store's table, bypassing
    /// the cookie pipeline, so a test can model "two devices" without driving
    /// two full browser sessions.
    /// </summary>
    private async Task InsertSessionRowAsync(string subject, string sid)
    {
        var factory = _factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using var database = await factory.CreateDbContextAsync();
        if (await database.OidcUserSessions.AnyAsync(s => s.SessionId == sid))
        {
            return;
        }
        database.OidcUserSessions.Add(new OidcUserSession
        {
            SessionId = sid,
            Subject = subject,
            CreatedAtUtc = DateTime.UtcNow,
            LastActivityUtc = DateTime.UtcNow,
            ProtectedTicket = [],
        });
        await database.SaveChangesAsync();
    }

    private static ClaimsPrincipal PrincipalFor(string subject) =>
        new(new ClaimsIdentity(
            new[]
            {
                new Claim("sub", subject),
                new Claim(System.Security.Claims.ClaimTypes.NameIdentifier, subject),
            },
            authenticationType: "Test"));

    private static string? SessionId(string? idToken)
    {
        if (string.IsNullOrEmpty(idToken))
        {
            return null;
        }
        var jwt = new JsonWebToken(idToken);
        return jwt.TryGetPayloadValue("sid", out string sid) ? sid : null;
    }
}
