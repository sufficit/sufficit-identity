using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Asserts against the nonce store the host actually resolves, not a class a
/// test chose. The handler that issues challenges was written for a stateless
/// store and says so; what it received for three weeks was a single-value one.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class DpopNonceChallengeTests(SufficitIdentityTestFactory factory)
{
    private const string Partition = "/connect/token|client-a|thumbprint-a";

    [Fact]
    public void A_second_challenge_does_not_invalidate_the_first()
    {
        // One client, one key, two token requests in flight. Both are
        // challenged; both must be able to retry. A store holding one value per
        // partition answers the second by overwriting the first, and the
        // client's own concurrency then fails its own retry.
        var store = factory.Services.GetRequiredService<IDpopNonceStore>();

        var first = store.Issue(Partition);
        var second = store.Issue(Partition);

        Assert.NotEqual(first, second);
        Assert.True(store.IsValid(first, Partition));
        Assert.True(store.IsValid(second, Partition));
    }

    [Fact]
    public void A_challenge_is_honored_by_a_replica_that_did_not_issue_it()
    {
        // Two stores that share only what replicas share — the data protection
        // key ring, which the host persists to the database — must agree.
        var issuing = factory.Services.GetRequiredService<IDpopNonceStore>();
        var nonce = issuing.Issue(Partition);

        var keyRing = factory.Services
            .GetRequiredService<IDataProtectionProvider>();
        var otherReplica = new ProtectedDpopNonceStore(keyRing);

        Assert.True(otherReplica.IsValid(nonce, Partition));
    }

    [Fact]
    public void A_challenge_belongs_to_one_client_and_one_key()
    {
        var store = factory.Services.GetRequiredService<IDpopNonceStore>();
        var nonce = store.Issue(Partition);

        Assert.False(store.IsValid(nonce, "/connect/token|client-b|thumbprint-a"));
        Assert.False(store.IsValid(nonce, "/connect/token|client-a|thumbprint-b"));
        Assert.False(store.IsValid(nonce, "/connect/par|client-a|thumbprint-a"));
    }
}
