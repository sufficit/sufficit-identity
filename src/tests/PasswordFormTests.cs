using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.UI;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class PasswordFormTests(SufficitIdentityTestFactory factory)
{
    [Theory]
    [InlineData(false, "success", "Senha alterada com sucesso.")]
    [InlineData(true, "success", "Senha redefinida com sucesso.")]
    [InlineData(false, "short", "Use pelo menos 8 caracteres.")]
    [InlineData(true, "short", "Use pelo menos 8 caracteres.")]
    [InlineData(false, "symbol", "Inclua um símbolo")]
    [InlineData(true, "symbol", "Inclua um símbolo")]
    [InlineData(false, "confirmation", "Digite a mesma senha nos dois campos")]
    [InlineData(true, "confirmation", "Digite a mesma senha nos dois campos")]
    [InlineData(false, "current", "A senha atual está incorreta.")]
    public async Task Browser_form_fields_reach_password_validation_and_report_the_result(
        bool reset, string scenario, string expected)
    {
        using var ui = CreateUiHost(factory);
        string userId, username, resetCode;
        await using (var scope = ui.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users,
                $"password-form-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
            userId = user.Id;
            username = user.UserName!;
            resetCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(
                await users.GeneratePasswordResetTokenAsync(user)));
        }
        using var client = ui.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://sts.tests.local"), AllowAutoRedirect = false,
        });
        if (!reset) (await client.GetAsync("/password-tests/signin/" + userId)).EnsureSuccessStatusCode();
        var url = reset ? QueryHelpers.AddQueryString("/account/resetpassword",
            new Dictionary<string, string?> { ["userId"] = userId, ["code"] = resetCode })
            : "/manage/changepassword";
        var response = await client.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains(reset ? "Use de 8 a 100" : "Use pelo menos 8", WebUtility.HtmlDecode(html));
        Assert.Contains("password-requirements", html);

        // Build the request from rendered controls, as the browser does. A
        // missing Name must fail here instead of a hand-built POST hiding it.
        var fields = ReadInputs(html);
        var passwordField = reset ? "_model.Password" : "_model.NewPassword";
        Assert.Contains(passwordField, fields.Keys);
        Assert.Contains("_model.ConfirmPassword", fields.Keys);
        var password = scenario switch
        {
            "short" => "Qx7!mZ2",
            "symbol" => "ReplacementPassword123",
            _ => "Qx7!mZ2p",
        };
        fields[passwordField] = password;
        fields["_model.ConfirmPassword"] = scenario == "confirmation" ? "Different!Password123" : password;
        if (!reset)
        {
            Assert.Contains("_model.OldPassword", fields.Keys);
            fields["_model.OldPassword"] = scenario == "current" ? "Wrong!Password123" : TestDataSeeder.DefaultPassword;
        }
        var posted = await client.PostAsync(url, new FormUrlEncodedContent(fields));
        posted.EnsureSuccessStatusCode();
        var result = WebUtility.HtmlDecode(await posted.Content.ReadAsStringAsync());
        Assert.Contains(expected, result);
        Assert.DoesNotContain("field is required", result);
        await using var verification = ui.Services.CreateAsyncScope();
        var manager = verification.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var changed = await manager.FindByIdAsync(userId);
        Assert.NotNull(changed);
        Assert.True(await manager.CheckPasswordAsync(changed,
            scenario == "success" ? password : TestDataSeeder.DefaultPassword));
    }

    [Fact]
    public async Task Guidance_uses_configured_runtime_requirements_and_localized_copy()
    {
        using var isolated = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Password:RequiredLength"] = "16",
            ["Sufficit:Identity:Password:RequireNonAlphanumeric"] = "false",
            ["Sufficit:Identity:Password:RequiredUniqueChars"] = "5",
            ["Sufficit:Identity:Password:RejectBreached"] = "true",
        });
        using var ui = CreateUiHost(isolated);
        using var client = ui.CreateClient();
        var html = WebUtility.HtmlDecode(await client.GetStringAsync("/account/register?culture=en-US&ui-culture=en-US"));
        Assert.Contains("Use 16 to 100 characters.", html);
        Assert.Contains("Use at least 5 distinct characters.", html);
        Assert.DoesNotContain("passwords exposed in data breaches", html);
        Assert.Contains("data-password-minimum=\"16\"", html);
        Assert.Contains("data-password-unique=\"5\"", html);
        Assert.DoesNotContain("Include a symbol", html);
        using var scope = ui.Services.CreateScope();
        var policy = scope.ServiceProvider.GetRequiredService<IAccountPasswordPolicyProvider>().GetPolicy();
        var runtime = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().Options.Password;
        Assert.Equal(runtime.RequiredLength, policy.RequiredLength);
        Assert.Equal(runtime.RequireNonAlphanumeric, policy.RequireNonAlphanumeric);
        Assert.Equal(runtime.RequiredUniqueChars, policy.RequiredUniqueChars);
    }

    private static WebApplicationFactory<SufficitIdentityTestFactory> CreateUiHost(
        SufficitIdentityTestFactory source) => source.WithWebHostBuilder(builder =>
    {
        builder.ConfigureServices(services =>
        {
            services.AddSufficitIdentityUI();
            services.AddCascadingAuthenticationState();
        });
        builder.Configure(app =>
        {
            app.UseRouting();
            app.UseRequestLocalization(new RequestLocalizationOptions().SetDefaultCulture("pt-BR")
                .AddSupportedCultures("pt-BR", "en-US").AddSupportedUICultures("pt-BR", "en-US"));
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseAntiforgery();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorComponents<Sufficit.Identity.UI.Components.App>().AddInteractiveServerRenderMode();
                endpoints.MapGet("/password-tests/signin/{id}", async (string id,
                    UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn) =>
                {
                    var user = await users.FindByIdAsync(id);
                    await signIn.SignInAsync(user!, false);
                    return Results.Ok();
                });
            });
        });
    });

    private static Dictionary<string, string> ReadInputs(string html)
    {
        // HTML attribute names are case-insensitive. Older SUI packages
        // forward Name as an input attribute; current SUI emits name directly.
        var result = new Dictionary<string, string>();
        foreach (Match input in Regex.Matches(html, @"<input\b[^>]*>", RegexOptions.IgnoreCase))
        {
            var name = Regex.Match(input.Value, "\\bname=\"([^\"]*)\"", RegexOptions.IgnoreCase);
            if (!name.Success) continue;
            var value = Regex.Match(input.Value, "\\bvalue=\"([^\"]*)\"", RegexOptions.IgnoreCase);
            result[WebUtility.HtmlDecode(name.Groups[1].Value)] = WebUtility.HtmlDecode(value.Groups[1].Value);
        }
        return result;
    }
}
