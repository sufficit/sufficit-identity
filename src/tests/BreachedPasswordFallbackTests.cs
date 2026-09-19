using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// What happens when the breach service does not answer. FailOpen lets every
/// password through and FailClosed stops every password change in the
/// deployment; these cover the third answer and the cache that makes an outage
/// stop mattering for a prefix already seen.
/// </summary>
public sealed class BreachedPasswordFallbackTests
{
    private const string KnownBreached = "123456";

    private static (string Prefix, string Suffix) Hash(string password)
    {
        var hex = Convert.ToHexString(
            System.Security.Cryptography.SHA1.HashData(
                System.Text.Encoding.UTF8.GetBytes(password)));
        return (hex[..5], hex[5..]);
    }

    private static BreachedPasswordValidator Validator(
        HttpMessageHandler handler,
        BreachedPasswordFailureMode mode,
        BreachedPasswordKnowledge? knowledge = null) =>
        new(
            new HttpClient(handler)
            {
                BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"),
            },
            NullLogger<BreachedPasswordValidator>.Instance,
            mode,
            knowledge ?? new BreachedPasswordKnowledge(new PasswordPolicyOptions()));

    [Theory]
    [InlineData(BreachedPasswordFailureMode.FailOpen, true)]
    [InlineData(BreachedPasswordFailureMode.LocalFallback, false)]
    [InlineData(BreachedPasswordFailureMode.FailClosed, false)]
    public async Task A_password_on_the_local_list_survives_an_outage_only_under_fail_open(
        BreachedPasswordFailureMode mode,
        bool accepted)
    {
        var validator = Validator(
            new UnavailableHandler(),
            mode);

        var result = await validator.ValidateAsync(null!, null!, KnownBreached);

        Assert.Equal(accepted, result.Succeeded);
        if (mode == BreachedPasswordFailureMode.LocalFallback)
        {
            // Named as what it is: the password is known breached, not merely
            // uncheckable.
            Assert.Contains(result.Errors, error => error.Code == "PasswordBreached");
        }
    }

    [Fact]
    public async Task A_password_the_fallback_does_not_know_is_accepted()
    {
        // The honest limit of a local answer: it can refuse what it knows and
        // must not pretend to know the rest.
        var validator = Validator(
            new UnavailableHandler(),
            BreachedPasswordFailureMode.LocalFallback);

        Assert.True((await validator.ValidateAsync(
            null!,
            null!,
            "a-password-no-corpus-has-ever-seen-8842")).Succeeded);
    }

    [Fact]
    public async Task A_deployment_list_adds_to_the_built_in_floor()
    {
        var path = Path.GetTempFileName();
        await File.WriteAllTextAsync(
            path,
            "# our own leak\nCompanyLeaked2019!\n\n   \n");
        try
        {
            var knowledge = new BreachedPasswordKnowledge(
                new PasswordPolicyOptions { LocalBreachedPasswordListPath = path });
            var validator = Validator(
                new UnavailableHandler(),
                BreachedPasswordFailureMode.LocalFallback,
                knowledge);

            Assert.False((await validator.ValidateAsync(
                null!, null!, "CompanyLeaked2019!")).Succeeded);
            // Comments and blank lines are not passwords.
            Assert.True((await validator.ValidateAsync(
                null!, null!, "# our own leak")).Succeeded);
            // And the floor is still there.
            Assert.False((await validator.ValidateAsync(
                null!, null!, KnownBreached)).Succeeded);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task An_unreadable_deployment_list_leaves_the_floor_in_place()
    {
        // Refusing to start over a missing file would trade a weaker fallback
        // for no service at all.
        var knowledge = new BreachedPasswordKnowledge(
            new PasswordPolicyOptions
            {
                LocalBreachedPasswordListPath =
                    Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.txt"),
            });

        Assert.False((await Validator(
            new UnavailableHandler(),
            BreachedPasswordFailureMode.LocalFallback,
            knowledge).ValidateAsync(null!, null!, KnownBreached)).Succeeded);
    }

    [Fact]
    public async Task A_range_already_answered_survives_the_outage_that_follows()
    {
        // The half that matters most: a prefix answered once covers every
        // password sharing it, so the outage never reaches those.
        const string password = "correct-horse-battery-staple-42";
        var (_, suffix) = Hash(password);
        var handler = new SequencedHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{suffix}:9\r\n"),
            });
        var knowledge = new BreachedPasswordKnowledge(new PasswordPolicyOptions());

        var first = await Validator(
            handler,
            BreachedPasswordFailureMode.FailClosed,
            knowledge)
            .ValidateAsync(null!, null!, password);
        Assert.False(first.Succeeded);
        Assert.Contains(first.Errors, error => error.Code == "PasswordBreached");

        // The service is gone now. The answer is still the same one, and it
        // did not go back to the network to get it.
        var offline = Validator(
            new UnavailableHandler(),
            BreachedPasswordFailureMode.FailClosed,
            knowledge);
        var second = await offline.ValidateAsync(null!, null!, password);

        Assert.False(second.Succeeded);
        Assert.Contains(second.Errors, error => error.Code == "PasswordBreached");
    }

    [Theory]
    // Not a range listing at all.
    [InlineData("<html>we are down for maintenance</html>")]
    // Right shape, wrong content: a suffix that is not 35 hex characters.
    [InlineData("NOTHEXNOTHEXNOTHEXNOTHEXNOTHEXNOTHEX:2\r\n")]
    [InlineData("")]
    public async Task An_unreadable_answer_is_an_outage_not_a_clean_bill_of_health(
        string body)
    {
        // A 200 carrying something else is the dangerous case: taking "no
        // match in this body" at face value would pass every password.
        var validator = Validator(
            new SequencedHandler(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            }),
            BreachedPasswordFailureMode.FailClosed);

        var result = await validator.ValidateAsync(null!, null!, "any-password");

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == "PasswordBreachCheckUnavailable");
    }

    [Fact]
    public async Task A_timeout_is_an_outage()
    {
        var validator = Validator(
            new ThrowingHandler(new TaskCanceledException("timed out")),
            BreachedPasswordFailureMode.FailClosed);

        Assert.False((await validator.ValidateAsync(
            null!, null!, "any-password")).Succeeded);
    }

    [Fact]
    public async Task The_check_recovers_when_the_service_comes_back()
    {
        const string password = "recovery-probe-91";
        var (_, suffix) = Hash(password);
        var handler = new SequencedHandler(
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent(string.Empty),
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{suffix}:3\r\n"),
            });
        var validator = Validator(
            handler,
            BreachedPasswordFailureMode.FailOpen,
            new BreachedPasswordKnowledge(new PasswordPolicyOptions()));

        // Degraded: accepted under FailOpen.
        Assert.True((await validator.ValidateAsync(null!, null!, password)).Succeeded);

        // Recovered: the same password is now refused on its merits.
        var recovered = await validator.ValidateAsync(null!, null!, password);
        Assert.False(recovered.Succeeded);
        Assert.Contains(recovered.Errors, error => error.Code == "PasswordBreached");
    }

    [Fact]
    public void The_range_cache_stays_within_its_bound()
    {
        var knowledge = new BreachedPasswordKnowledge(
            new PasswordPolicyOptions { BreachedRangeCacheSize = 4 });

        for (var index = 0; index < 20; index++)
        {
            knowledge.StoreRange($"{index:X5}", new HashSet<string> { "AAAA" });
        }

        var retained = Enumerable.Range(0, 20)
            .Count(index => knowledge.TryGetRange($"{index:X5}") is not null);
        Assert.InRange(retained, 1, 4);
    }

    private sealed class UnavailableHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent(string.Empty),
            });
    }

    private sealed class ThrowingHandler(Exception failure) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw failure;
    }

    private sealed class SequencedHandler(params HttpResponseMessage[] responses)
        : HttpMessageHandler
    {
        private int _index;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = responses[Math.Min(_index, responses.Length - 1)];
            _index++;
            return Task.FromResult(response);
        }
    }
}
