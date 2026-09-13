using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The password grant must not reveal which usernames exist: an unknown
/// account still pays a password hash verification and gets the same generic
/// error as a wrong password.
/// </summary>
public sealed class PasswordGrantEnumerationTests
{
    [Fact]
    public async Task Unknown_username_still_verifies_a_password_hash()
    {
        using var parent = new SufficitIdentityTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        var counter = new CountingPasswordHasher();
        using var app = parent.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IPasswordHasher<ApplicationUser>>();
            services.AddSingleton<IPasswordHasher<ApplicationUser>>(counter);
        }));
        var client = app.CreateClient();

        var (unknownStatus, unknownBody) = await PasswordGrantAsync(
            client, $"missing-{Guid.NewGuid():N}", "Wrong!Passw0rd#9");
        var unknownVerifications = counter.Verifications;

        var (wrongStatus, wrongBody) = await PasswordGrantAsync(
            client, TestDataSeeder.DefaultUsername, "Wrong!Passw0rd#9");

        Assert.Equal(HttpStatusCode.BadRequest, unknownStatus);
        Assert.Equal(HttpStatusCode.BadRequest, wrongStatus);
        Assert.Equal("invalid_grant", unknownBody.GetProperty("error").GetString());
        Assert.Equal(
            wrongBody.GetProperty("error_description").GetString(),
            unknownBody.GetProperty("error_description").GetString());
        Assert.True(unknownVerifications >= 1,
            "An unknown username must still run a password hash verification.");
    }

    private static Task<(HttpStatusCode, System.Text.Json.JsonElement)> PasswordGrantAsync(
        HttpClient client,
        string username,
        string password) =>
        client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

    private sealed class CountingPasswordHasher : IPasswordHasher<ApplicationUser>
    {
        private readonly PasswordHasher<ApplicationUser> _inner = new();
        private int _verifications;

        public int Verifications => _verifications;

        public string HashPassword(ApplicationUser user, string password) =>
            _inner.HashPassword(user, password);

        public PasswordVerificationResult VerifyHashedPassword(
            ApplicationUser user,
            string hashedPassword,
            string providedPassword)
        {
            Interlocked.Increment(ref _verifications);
            return _inner.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }
}
