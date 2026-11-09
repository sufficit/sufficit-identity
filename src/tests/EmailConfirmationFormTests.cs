using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.UI;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class EmailConfirmationFormTests(SufficitIdentityTestFactory factory)
{
    [Theory]
    [InlineData("valid")]
    [InlineData("invalid")]
    [InlineData("malformed")]
    [InlineData("missing")]
    [InlineData("expired")]
    public async Task Confirmation_page_reports_result_and_offers_recovery_only_after_failure(
        string scenario)
    {
        using var ui = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.AddSufficitIdentityUI();
                services.AddCascadingAuthenticationState();
                if (scenario == "expired")
                    services.Configure<DataProtectionTokenProviderOptions>(options =>
                        options.TokenLifespan = TimeSpan.FromSeconds(-1));
            });
            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseRequestLocalization(new RequestLocalizationOptions().SetDefaultCulture("pt-BR")
                    .AddSupportedCultures("pt-BR").AddSupportedUICultures("pt-BR"));
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseAntiforgery();
                app.UseEndpoints(endpoints => endpoints.MapRazorComponents<Sufficit.Identity.UI.Components.App>()
                    .AddInteractiveServerRenderMode());
            });
        });
        string userId;
        string? code;
        await using (var scope = ui.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users,
                $"email-confirmation-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
            user.EmailConfirmed = false;
            Assert.True((await users.UpdateAsync(user)).Succeeded);
            userId = user.Id;
            code = scenario switch
            {
                "missing" => null,
                "malformed" => "!",
                "invalid" => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("invalid-token")),
                _ => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(
                    await users.GenerateEmailConfirmationTokenAsync(user))),
            };
        }
        using var client = ui.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://sts.tests.local"), AllowAutoRedirect = false,
        });
        var url = QueryHelpers.AddQueryString("/account/confirmemail", new Dictionary<string, string?>
        {
            ["userId"] = userId, ["code"] = code,
        });
        var response = await client.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());
        if (scenario == "valid")
        {
            Assert.Contains("E-mail confirmado com sucesso!", html);
            Assert.DoesNotContain("href=\"/account/resendemailconfirmation\"", html);
        }
        else
        {
            Assert.Contains("Link inválido ou expirado.", html);
            Assert.DoesNotContain("Invalid token.", html);
            Assert.Contains("href=\"/account/resendemailconfirmation\"", html);
            Assert.Contains("Solicitar novo link", html);
        }
        Assert.Contains("Voltar ao login", html);
        await using var verificationScope = ui.Services.CreateAsyncScope();
        var verifiedUser = await verificationScope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>().FindByIdAsync(userId);
        Assert.Equal(scenario == "valid", verifiedUser!.EmailConfirmed);
    }
}
