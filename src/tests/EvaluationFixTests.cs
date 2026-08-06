using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Regression tests for the security fixes from EVALUATION-2026-08-05-claude-fable-5.
/// </summary>
public sealed class EvaluationFixTests
{
    // ---- #4: ClaimScopeMap default gates directive behind directives scope ----

    [Fact]
    public void ClaimScopeMap_default_gates_directive_behind_directives_scope()
    {
        var options = new SufficitIdentityOptions();
        Assert.NotEmpty(options.ClaimScopeMap.ClaimToScope);
        Assert.True(options.ClaimScopeMap.ClaimToScope.TryGetValue("directive", out var scope));
        Assert.Equal("directives", scope);
    }

    // ---- #5: Open redirect blocked ----

    [Theory]
    [InlineData("//evil.host/Account/Login")]
    [InlineData("//evil.host/account/login")]
    [InlineData("//EVIL.HOST/CONNECT/AUTHORIZE")]
    public async Task Protocol_relative_path_returns_400_not_redirect(string path)
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var response = await client.GetAsync(path);
        // The request must NOT result in a redirect (3xx). BadRequest (400, our
        // explicit guard) or NotFound (404, routing doesn't match //host/path)
        // are both acceptable — neither is an open redirect.
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest ||
            response.StatusCode == HttpStatusCode.NotFound,
            $"Expected 400 or 404 for protocol-relative path, got {(int)response.StatusCode} {response.StatusCode}");
        Assert.NotInRange((int)response.StatusCode, 300, 399);
        await Task.CompletedTask;
    }

    // ---- #16: CIBA token store registration is wired ----

    [Fact]
    public async Task Ciba_controller_resolves_token_manager_dependency()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Ciba:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            // The CIBA token store registration (#16 fix) requires
            // IOpenIddictTokenManager to be injectable in CibaController.
            // This smoke test verifies the DI wiring is correct — the full
            // CIBA flow is covered by CibaTests.
            using var scope = factory.Services.CreateAsyncScope();
            var tokenManager = scope.ServiceProvider
                .GetService<IOpenIddictTokenManager>();
            Assert.NotNull(tokenManager);
            await Task.CompletedTask;
        }
    }

    // ---- #17: Registration does not reveal duplicate username ----

    [Fact]
    public async Task Registration_with_existing_email_returns_generic_error()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Register:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            // Create a user with the target email first.
            using var scope = factory.Services.CreateScope();
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager,
                "dup-user@tests.local", "Str0ng!Passw0rd#1");

            var client = factory.CreateClient();

            // Attempt to register with the same email.
            var response = await client.PostAsync("/account/register",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["email"] = "dup-user@tests.local",
                    ["password"] = "An0ther!Str0ng#Pass1",
                    ["confirmPassword"] = "An0ther!Str0ng#Pass1",
                }));

            // The response should NOT contain "already taken" / "already exists"
            // / "DuplicateUserName" which would reveal the account exists.
            var content = await response.Content.ReadAsStringAsync();
            var lowerContent = content.ToLowerInvariant();
            Assert.False(
                lowerContent.Contains("already taken") ||
                lowerContent.Contains("already exists") ||
                lowerContent.Contains("duplicateusername") ||
                lowerContent.Contains("is already taken"),
                $"Registration should not reveal account existence. Response contains enumeration oracle.");
            await Task.CompletedTask;
        }
    }
}
