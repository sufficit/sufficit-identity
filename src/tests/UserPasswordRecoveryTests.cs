using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class UserPasswordRecoveryTests
{
    private sealed class Mail : IEmailSender
    {
        public bool Fail;
        public string? Address, Body;
        public int Calls;
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            Calls++;
            if (Fail) throw new InvalidOperationException("synthetic mail failure");
            Address = email; Body = htmlMessage;
            return Task.CompletedTask;
        }
    }

    [Theory]
    [InlineData("confirmed", HttpStatusCode.NoContent, "user_password_recovery_queued")]
    [InlineData("unconfirmed", HttpStatusCode.Conflict, "user_email_unconfirmed")]
    [InlineData("missing", HttpStatusCode.Conflict, "user_email_missing")]
    [InlineData("failure", HttpStatusCode.Conflict, "user_password_recovery_failed")]
    [InlineData("not-found", HttpStatusCode.NotFound, "user_not_found")]
    public async Task Recovery_dispatch_is_audited_and_only_user_changes_password(string scenario, HttpStatusCode expected, string reason)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var mail = new Mail { Fail = scenario == "failure" };
        using var app = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(mail);
        }));
        var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await manager.FindByNameAsync(TestDataSeeder.DefaultUsername))!;
        if (scenario == "unconfirmed") user.EmailConfirmed = false;
        if (scenario == "missing") user.Email = null;
        Assert.True((await manager.UpdateAsync(user)).Succeeded);
        var hash = user.PasswordHash;
        var stamp = user.SecurityStamp;
        var id = scenario == "not-found" ? Guid.NewGuid().ToString() : user.Id;
        using var response = await client.PostAsync($"/api/users/{id}/password-recovery", null);
        Assert.Equal(expected, response.StatusCode);
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Entry(user).ReloadAsync();
        Assert.Equal(hash, user.PasswordHash);
        Assert.Equal(stamp, user.SecurityStamp);
        Assert.True(await manager.CheckPasswordAsync(user, TestDataSeeder.DefaultPassword));
        Assert.True(await db.ManagementAuditEvents.AnyAsync(e => e.ResourceId == id && e.ReasonCode == reason));
        if (scenario != "confirmed")
        {
            Assert.Null(mail.Body);
            Assert.Equal(scenario == "failure" ? 1 : 0, mail.Calls);
            return;
        }
        Assert.Equal(user.Email, mail.Address);
        Assert.Equal(1, mail.Calls);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        var url = WebUtility.HtmlDecode(Regex.Match(mail.Body!, "href=\"([^\"]+)\"").Groups[1].Value);
        var query = QueryHelpers.ParseQuery(new Uri(url).Query);
        Assert.Equal(user.Id, query["userId"].ToString());
        var accounts = scope.ServiceProvider.GetRequiredService<IAccountOnboardingService>();
        var result = await accounts.ResetPasswordAsync(new AccountPasswordResetCommand(user.Id,
            query["code"].ToString(), "CustomerChosen!Passw0rd#84"));
        Assert.Equal(AccountPasswordResetStatus.Succeeded, result.Status);
        await db.Entry(user).ReloadAsync();
        Assert.True(await manager.CheckPasswordAsync(user, "CustomerChosen!Passw0rd#84"));
        Assert.False(await manager.CheckPasswordAsync(user, TestDataSeeder.DefaultPassword));
    }

    [Theory]
    [InlineData(ManagementCapabilities.UsersRecovery)]
    [InlineData(ManagementCapabilities.UsersReset)]
    public async Task Either_capability_sends_the_link_and_the_audit_names_the_one_used(string capability)
    {
        await using var fixture = await OperatorFixture.CreateAsync(new OnlyTheseCapabilities(capability));
        using var response = await fixture.Client.PostAsync($"/api/users/{fixture.Target.Id}/password-recovery", null);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(1, fixture.Mail.Calls);
        var audit = await fixture.Database.ManagementAuditEvents.SingleAsync(e => e.ReasonCode == "user_password_recovery_queued");
        Assert.Equal(capability, audit.Capability);
    }

    [Fact]
    public async Task Recovery_capability_cannot_set_a_password()
    {
        await using var fixture = await OperatorFixture.CreateAsync(new OnlyTheseCapabilities(
            ManagementCapabilities.UsersRecovery, ManagementCapabilities.UsersRead));
        var detail = await fixture.Client.GetFromJsonAsync<ManagementUserDetail>($"/api/users/{fixture.Target.Id}");
        Assert.True(detail!.Actions.CanRequestPasswordRecovery);
        Assert.False(detail.Actions.CanResetPassword);
        using var response = await fixture.Client.PostAsJsonAsync($"/api/users/{fixture.Target.Id}/reset-password",
            new ResetManagementUserPasswordCommand("Operator!Chosen#Passw0rd84"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var manager = fixture.Scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.True(await manager.CheckPasswordAsync(fixture.Target, TestDataSeeder.DefaultPassword));
    }

    [Fact]
    public async Task Without_either_capability_the_refusal_is_audited_under_the_narrow_one()
    {
        await using var fixture = await OperatorFixture.CreateAsync(new OnlyTheseCapabilities(ManagementCapabilities.UsersRead));
        using var response = await fixture.Client.PostAsync($"/api/users/{fixture.Target.Id}/password-recovery", null);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, fixture.Mail.Calls);
        var audit = await fixture.Database.ManagementAuditEvents.SingleAsync(e => e.ResourceId == fixture.Target.Id);
        Assert.Equal(ManagementCapabilities.UsersRecovery, audit.Capability);
        Assert.Equal("capability_not_granted", audit.ReasonCode);
    }

    [Fact]
    public async Task Reset_holder_without_second_factor_is_asked_for_it()
    {
        await using var fixture = await OperatorFixture.CreateAsync(new ResetNeedsSecondFactor());
        using var response = await fixture.Client.PostAsync($"/api/users/{fixture.Target.Id}/password-recovery", null);
        Assert.Equal(0, fixture.Mail.Calls);
        var audit = await fixture.Database.ManagementAuditEvents.SingleAsync(e => e.ResourceId == fixture.Target.Id);
        Assert.Equal(ManagementCapabilities.UsersReset, audit.Capability);
        Assert.Equal("mfa_required", audit.ReasonCode);
    }

    private sealed class OnlyTheseCapabilities(params string[] capabilities) : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(ClaimsPrincipal principal, string capability,
            ManagementResource resource, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capabilities.Contains(capability)
                ? ManagementAuthorizationDecision.Allowed()
                : ManagementAuthorizationDecision.Denied("capability_not_granted", capability));
    }

    private sealed class ResetNeedsSecondFactor : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(ClaimsPrincipal principal, string capability,
            ManagementResource resource, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capability == ManagementCapabilities.UsersReset
                ? ManagementAuthorizationDecision.StepUpRequired("mfa_required", capability)
                : ManagementAuthorizationDecision.Denied("capability_not_granted", capability));
    }

    private sealed class OperatorFixture : IAsyncDisposable
    {
        private readonly ManagementTestFactory factory;
        private readonly WebApplicationFactory<ManagementTestFactory> host;
        public AsyncServiceScope Scope { get; }
        public HttpClient Client { get; }
        public Mail Mail { get; }
        public AppDbContext Database => Scope.ServiceProvider.GetRequiredService<AppDbContext>();
        public ApplicationUser Target { get; private set; } = null!;

        private OperatorFixture(ManagementTestFactory factory, WebApplicationFactory<ManagementTestFactory> host, Mail mail)
        {
            this.factory = factory;
            this.host = host;
            Mail = mail;
            Scope = host.Services.CreateAsyncScope();
            Client = host.CreateClient();
        }

        public static async Task<OperatorFixture> CreateAsync(IManagementAuthorizationEvaluator evaluator)
        {
            var factory = new ManagementTestFactory();
            await ((IAsyncLifetime)factory).InitializeAsync();
            var mail = new Mail();
            var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IEmailSender>();
                services.AddSingleton<IEmailSender>(mail);
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddSingleton(evaluator);
            }));
            var fixture = new OperatorFixture(factory, host, mail);
            fixture.Target = (await fixture.Scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>()
                .FindByNameAsync(TestDataSeeder.DefaultUsername))!;
            return fixture;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await Scope.DisposeAsync();
            await host.DisposeAsync();
            await factory.DisposeAsync();
        }
    }

    [Fact]
    public async Task Anonymous_operator_cannot_request_recovery()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var response = await factory.CreateClient().PostAsync($"/api/users/{Guid.NewGuid()}/password-recovery", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
