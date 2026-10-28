using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.SystemUsers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Trait("Category", "BrowserHost")]
    [Fact]
    public async Task System_users_browser_flow()
    {
        var script = BrowserHostScript.Resolve("IDENTITY_SYSTEM_USERS_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        await using var app = await CreateHostAsync(
            useKestrel: true,
            services => services.AddSingleton<ISystemUserManagementService, InMemorySystemUserManagementService>());
        var start = new ProcessStartInfo("node") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(app.Urls.Single());
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        Assert.True(process.ExitCode == 0, await stdout + "\n" + await stderr);
    }

    /// <summary>Just enough state for the page to be exercised in a browser.</summary>
    private sealed class InMemorySystemUserManagementService : ISystemUserManagementService
    {
        private readonly List<SystemUserSummary> _users = [];
        private readonly Dictionary<string, List<SystemUserEnrollmentSummary>> _enrollments = [];

        public Task<IReadOnlyList<SystemUserSummary>> ListAsync(
            ManagementRequestContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SystemUserSummary>>(_users.ToArray());

        public Task<SystemUserSummary> CreateAsync(
            CreateSystemUserCommand command, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            if (_users.Any(user => user.UserName == command.UserName))
                throw new ManagementConflictException("system_user_name_taken", "A user with this name already exists.");
            var created = new SystemUserSummary(Guid.NewGuid().ToString(), command.UserName, command.DisplayName,
                "operator-subject", DateTime.UtcNow, false, 0);
            _users.Add(created);
            _enrollments[created.UserId] = [];
            return Task.FromResult(created);
        }

        public Task<IReadOnlyList<string>> GetEntitlementsAsync(
            string userId, ManagementRequestContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>([]);

        public Task<IReadOnlyList<string>> SetEntitlementsAsync(
            string userId, SetSystemUserEntitlementsCommand command, ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>([.. command.Entitlements ?? []]);

        public Task<SystemUserSummary> ToggleAsync(
            string userId, bool? enabled, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            var index = _users.FindIndex(user => user.UserId == userId);
            var disable = !(enabled ?? _users[index].Disabled);
            _users[index] = _users[index] with
            {
                Disabled = disable, ActiveCredentials = disable ? 0 : _users[index].ActiveCredentials,
            };
            return Task.FromResult(_users[index]);
        }

        public Task<IReadOnlyList<SystemUserEnrollmentSummary>> ListEnrollmentsAsync(
            string userId, ManagementRequestContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SystemUserEnrollmentSummary>>(_enrollments[userId].ToArray());

        public Task<SystemUserEnrollmentIssueResult> IssueEnrollmentAsync(
            string userId, IssueSystemUserEnrollmentCommand command, ManagementRequestContext context,
            CancellationToken cancellationToken = default)
        {
            if (command.ClientId != "headless-agent")
                throw new ManagementValidationException("system_user_enrollment_client_not_allowed",
                    "The client must exist and allow both the system-user enrollment grant and refresh tokens.", "clientId");
            var enrollment = new SystemUserEnrollmentSummary(Guid.NewGuid(), command.ClientId, command.Label,
                "abc123def456", "operator-subject", DateTime.UtcNow, DateTime.UtcNow.AddHours(command.LifetimeHours ?? 24),
                null, null, SystemUserEnrollmentStatus.Pending);
            _enrollments[userId].Insert(0, enrollment);
            return Task.FromResult(new SystemUserEnrollmentIssueResult(
                enrollment, "sys_enroll_stub-enrollment-code", SystemUserEnrollmentProtocol.GrantType));
        }

        public Task RevokeEnrollmentAsync(
            string userId, Guid enrollmentId, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            var list = _enrollments[userId];
            var index = list.FindIndex(item => item.Id == enrollmentId);
            list[index] = list[index] with { RevokedAtUtc = DateTime.UtcNow, Status = SystemUserEnrollmentStatus.Revoked };
            return Task.CompletedTask;
        }

        private readonly Dictionary<string, List<SystemUserClientSummary>> _clients = new(StringComparer.Ordinal);

        public Task<IReadOnlyList<SystemUserClientSummary>> ListClientsAsync(
            string userId, ManagementRequestContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SystemUserClientSummary>>(
                _clients.TryGetValue(userId, out var list) ? [.. list] : []);

        public Task<SystemUserClientSummary> BindClientAsync(
            string userId, string clientId, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            var summary = new SystemUserClientSummary(clientId, null);
            if (!_clients.TryGetValue(userId, out var list))
            {
                _clients[userId] = list = [];
            }

            list.Add(summary);
            return Task.FromResult(summary);
        }

        public Task UnbindClientAsync(
            string userId, string clientId, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            if (_clients.TryGetValue(userId, out var list))
            {
                list.RemoveAll(item => item.ClientId == clientId);
            }

            return Task.CompletedTask;
        }
    }
}
