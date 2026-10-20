using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The owner's client revokes the delegated credential of a cloud executor it retires.
/// A suspended executor cannot revoke its own, so without this the credential stayed
/// active and counted toward the per-user cap (seen in production 2026-10-13).
/// </summary>
public sealed class PersonalDelegatedCredentialRevocationTests
{
    private static readonly Guid Device = Guid.Parse("324692f0-5e91-47e2-a539-99e7b527f846");

    [Fact]
    public async Task Revokes_only_the_callers_credentials_for_that_device()
    {
        var access = new RecordingAccess(
            new AccountDelegatedCredential("a1", "example-app-executor", "Executor",
                Device.ToString("D"), "example-app", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(30)),
            new AccountDelegatedCredential("a2", "example-app-executor", "Executor",
                Guid.NewGuid().ToString("D"), "example-app", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(30)));
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<IAccountAccessService>(access)));
        using var client = host.CreateClient();
        await IdentityMcpTests.AuthenticateAsync(client);

        using var response = await client.PostAsync(
            $"/api/account/personal/delegated-credentials/revoke?label={Device:D}", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Equal(["a1"], access.Revoked);
        // The account service is asked about the bearer's own subject, never a chosen one.
        Assert.NotNull(access.Subject);
        Assert.All(access.Subjects, subject => Assert.Equal(access.Subject, subject));
    }

    [Fact]
    public async Task A_label_that_is_not_a_device_id_is_refused()
    {
        var access = new RecordingAccess();
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<IAccountAccessService>(access)));
        using var client = host.CreateClient();
        await IdentityMcpTests.AuthenticateAsync(client);

        using var response = await client.PostAsync(
            "/api/account/personal/delegated-credentials/revoke?label=not-a-guid", null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(access.Revoked);
    }

    private sealed class RecordingAccess(params AccountDelegatedCredential[] credentials) : IAccountAccessService
    {
        public List<string> Revoked { get; } = [];
        public List<string?> Subjects { get; } = [];
        public string? Subject => Subjects.FirstOrDefault();

        private void See(ClaimsPrincipal principal) =>
            Subjects.Add(principal.FindFirst(new IdentityOptions().ClaimsIdentity.UserIdClaimType)?.Value
                ?? principal.Claims.FirstOrDefault()?.Value);

        public Task<IReadOnlyList<AccountDelegatedCredential>> GetDelegatedCredentialsAsync(
            ClaimsPrincipal principal, CancellationToken cancellationToken = default)
        {
            See(principal);
            return Task.FromResult<IReadOnlyList<AccountDelegatedCredential>>(credentials);
        }

        public Task<AccountSelfServiceResult> RevokeDelegatedCredentialAsync(
            ClaimsPrincipal principal, string credentialId, CancellationToken cancellationToken = default)
        {
            See(principal);
            Revoked.Add(credentialId);
            return Task.FromResult(AccountSelfServiceResult.Success);
        }

        public Task<IReadOnlyList<AccountConnectedApplication>> GetConnectedApplicationsAsync(
            ClaimsPrincipal principal, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<AccountSessionCredential>> GetSessionsAsync(
            ClaimsPrincipal principal, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<AccountSelfServiceResult> RevokeConnectedApplicationAsync(
            ClaimsPrincipal principal, string applicationId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<AccountSelfServiceResult> RevokeSessionAsync(
            ClaimsPrincipal principal, string sessionId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<AccountSelfServiceResult> RevokeAllSessionsAsync(
            ClaimsPrincipal principal, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
