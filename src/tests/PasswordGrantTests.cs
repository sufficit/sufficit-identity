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
}
