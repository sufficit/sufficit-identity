using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>Plan D6: a public email request takes the same minimum time whether or not the account exists.</summary>
public sealed class PublicEmailRequestTimingTests
{
    [Fact]
    public void A_fast_answer_waits_up_to_the_floor_and_a_slow_one_waits_nothing()
    {
        var floor = AspNetCoreIdentityAccountOnboardingService.PublicEmailRequestFloor;

        // A missing account answers at once: it waits the whole floor.
        Assert.Equal(floor, AspNetCoreIdentityAccountOnboardingService.RemainingToFloor(TimeSpan.Zero));
        // An existing one spent time on the token and SMTP: it waits only the rest.
        Assert.Equal(floor - TimeSpan.FromMilliseconds(400),
            AspNetCoreIdentityAccountOnboardingService.RemainingToFloor(TimeSpan.FromMilliseconds(400)));
        Assert.Equal(TimeSpan.Zero, AspNetCoreIdentityAccountOnboardingService.RemainingToFloor(floor + TimeSpan.FromSeconds(3)));
    }
}
