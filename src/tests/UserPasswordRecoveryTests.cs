using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
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

    [Fact]
    public async Task Anonymous_operator_cannot_request_recovery()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var response = await factory.CreateClient().PostAsync($"/api/users/{Guid.NewGuid()}/password-recovery", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
