using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.SharedSignals;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the least-privilege behaviour of SSF stream subscriptions: an empty
/// events_requested list subscribes to nothing (it used to mean "every
/// supported event type", so the least specific request produced the broadest
/// delivery — every CAEP signal for every subject).
/// </summary>
public sealed class SsfSubscriptionMatcherTests
{
    private const string SessionRevoked =
        CaepEventGenerator.SessionRevokedEventType;
    private const string CredentialChange =
        CaepEventGenerator.CredentialChangeEventType;

    private static SsfStream Stream(string events, string subject = "ALL") =>
        new()
        {
            StreamId = "stream-1",
            OwnerClientId = "client-1",
            Audience = "https://receiver.tests.local/events",
            EventsRequested = events,
            SubjectScope = subject,
        };

    [Fact]
    public void Empty_event_list_matches_nothing()
    {
        // Fail closed: a stream that subscribes to no event type receives no
        // event, rather than silently receiving all of them.
        var matcher = new SsfSubscriptionMatcher();

        Assert.False(matcher.Matches(Stream("[]"), "user-1", SessionRevoked));
        Assert.False(matcher.Matches(Stream("[]"), "user-1", CredentialChange));
    }

    [Fact]
    public void Listed_event_matches_and_unlisted_does_not()
    {
        var matcher = new SsfSubscriptionMatcher();
        var stream = Stream($"[\"{SessionRevoked}\"]");

        Assert.True(matcher.Matches(stream, "user-1", SessionRevoked));
        Assert.False(matcher.Matches(stream, "user-1", CredentialChange));
    }

    [Fact]
    public void Malformed_event_list_matches_nothing()
    {
        var matcher = new SsfSubscriptionMatcher();

        Assert.False(matcher.Matches(Stream("not-json"), "user-1", SessionRevoked));
        Assert.False(matcher.Matches(Stream("{}"), "user-1", SessionRevoked));
    }

    [Fact]
    public void Subject_scope_still_gates_delivery()
    {
        var matcher = new SsfSubscriptionMatcher();
        var events = $"[\"{SessionRevoked}\"]";

        Assert.True(matcher.Matches(Stream(events, "ALL"), "user-1", SessionRevoked));
        Assert.True(matcher.Matches(Stream(events, "user-1"), "user-1", SessionRevoked));
        Assert.False(matcher.Matches(Stream(events, "user-2"), "user-1", SessionRevoked));
    }
}
