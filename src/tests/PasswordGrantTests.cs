using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class PasswordGrantTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public PasswordGrantTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Password_grant_with_valid_credentials_issues_an_access_token()
    {
        var client = _factory.CreateClient();

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrEmpty(body.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task Password_grant_with_wrong_password_fails_with_generic_invalid_grant()
    {
        var client = _factory.CreateClient();

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = "definitely-the-wrong-password",
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        AssertGenericInvalidGrant(status, body);
    }

    [Fact]
    public async Task Password_grant_with_unknown_username_fails_with_the_same_generic_message_as_wrong_password()
    {
        var client = _factory.CreateClient();

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = $"nobody-{Guid.NewGuid():N}",
            ["password"] = "whatever",
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        // Same assertion, same generic message: no user-existence leak.
        AssertGenericInvalidGrant(status, body);
    }

    [Fact]
    public async Task Five_failed_attempts_lock_the_account_out_even_for_the_subsequent_correct_password()
    {
        // Dedicated user: avoids cross-test pollution of the shared
        // TestDataSeeder.DefaultUsername account's lockout counter.
        var username = $"lockout-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#2";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient();

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = "wrong-password",
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            });

            AssertGenericInvalidGrant(status, body);
        }

        // 6th attempt, this time with the CORRECT password: still rejected
        // because ASP.NET Core Identity's default lockout policy
        // (MaxFailedAccessAttempts = 5) has now kicked in.
        var (lockedStatus, lockedBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        AssertGenericInvalidGrant(lockedStatus, lockedBody);
    }

    private static void AssertGenericInvalidGrant(HttpStatusCode status, System.Text.Json.JsonElement body)
    {
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.Equal("Invalid username or password.", body.GetProperty("error_description").GetString());
    }

    // ----------------------------------------------------------------------
    // Item 2.2 [M2] — password complexity policy (RequiredLength=12 default).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Creating_a_user_with_a_password_below_required_length_fails()
    {
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var user = new ApplicationUser
        {
            UserName = $"shortpw-{Guid.NewGuid():N}",
            Email = $"shortpw-{Guid.NewGuid():N}@tests.local",
            EmailConfirmed = true,
        };

        // 8 chars, satisfies NIST floor but NOT the configured RequiredLength
        // (default 12) — the configured policy must reject it.
        var result = await userManager.CreateAsync(user, "Abcd123!");

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Code.Contains("PasswordTooShort", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Creating_a_user_with_a_strong_password_succeeds()
    {
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var username = $"strongpw-{Guid.NewGuid():N}";
        var user = new ApplicationUser
        {
            UserName = username,
            Email = $"{username}@tests.local",
            EmailConfirmed = true,
        };

        // ≥12 chars, upper+lower+digit+non-alphanumeric, >4 unique — satisfies
        // every dimension of the configured PasswordPolicyOptions.
        var result = await userManager.CreateAsync(user, "Str0ng!Passw0rd#Z");

        Assert.True(result.Succeeded);
    }

    // ----------------------------------------------------------------------
    // Item 2.3 [M3] — RequireConfirmedEmail collapses unconfirmed users into
    // the SAME generic invalid_grant as a wrong password (anti-enumereration).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Password_grant_for_user_with_unconfirmed_email_fails_with_the_same_generic_message_as_wrong_password()
    {
        // Dedicated user with EmailConfirmed=false. The default policy
        // (SignIn.RequireConfirmedEmail=true) makes CanSignInAsync return false
        // for this user, so ExchangeForPasswordAsync collapses them into the
        // generic invalid_grant — identical to the wrong-password case below.
        var username = $"unconfirmed-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Y";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);

            // Flip the seeded user to unconfirmed (CreateUserAsync always sets
            // EmailConfirmed=true; this test needs the opposite).
            var stored = await userManager.FindByNameAsync(username);
            Assert.NotNull(stored);
            // "Unconfirm" by directly flipping the column — there is no
            // "unconfirm" API, so set it false at the store level.
            stored!.EmailConfirmed = false;
            await userManager.UpdateAsync(stored);
        }

        var client = _factory.CreateClient();

        // Correct password but unconfirmed email.
        var (unconfirmedStatus, unconfirmedBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        // Wrong password for the SAME user — the reference case the
        // unconfirmed case must match byte-for-byte (no enumeration leak).
        var (wrongPwStatus, wrongPwBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = "definitely-the-wrong-password",
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        // Both must be the generic invalid_grant with the identical message.
        AssertGenericInvalidGrant(unconfirmedStatus, unconfirmedBody);
        AssertGenericInvalidGrant(wrongPwStatus, wrongPwBody);
        Assert.Equal(
            unconfirmedBody.GetProperty("error_description").GetString(),
            wrongPwBody.GetProperty("error_description").GetString());
    }
}
