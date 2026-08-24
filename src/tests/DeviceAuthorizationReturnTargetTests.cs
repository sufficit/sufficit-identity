using Sufficit.Identity.Application.Accounts;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DeviceAuthorizationReturnTargetTests
{
    [Theory]
    [InlineData(DeviceAuthorizationReturnTargets.Genius, DeviceAuthorizationReturnTargets.Genius)]
    [InlineData("SUFFICIT-GENIUS://auth-complete", null)]
    [InlineData("sufficit-genius://auth-complete/extra", null)]
    [InlineData("javascript:alert(1)", null)]
    [InlineData("https://attacker.example/", null)]
    [InlineData("", null)]
    public void Normalize_accepts_only_the_known_tokenless_callback(
        string candidate,
        string? expected) =>
        Assert.Equal(expected, DeviceAuthorizationReturnTargets.Normalize(candidate));
}
