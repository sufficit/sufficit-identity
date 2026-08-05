using Sufficit.Identity.Application.Accounts;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class LocalUrlValidatorTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/connect/authorize?client_id=legacy-blazor-client&state=abc")]
    [InlineData("~/account/login?returnUrl=%2Fconnect%2Fauthorize")]
    public void Allows_local_paths_with_query_strings(string url)
        => Assert.True(LocalUrlValidator.IsLocal(url));

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/\\evil.example/")]
    [InlineData("javascript:alert(1)")]
    public void Rejects_external_and_ambiguous_urls(string url)
        => Assert.False(LocalUrlValidator.IsLocal(url));
}
