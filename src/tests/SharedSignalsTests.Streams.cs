using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.SharedSignals;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class SharedSignalsTests
{
    [Fact]
    public async Task Discovery_exposes_configuration_endpoint_when_stream_management_enabled()
    {
        using var enabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
                ["Sufficit:Identity:SharedSignals:StreamManagementEnabled"] = "true",
            });
        await ((IAsyncLifetime)enabled).InitializeAsync();
        using var response = await enabled.CreateClient().GetAsync(
            "/.well-known/ssf-configuration");
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("/ssf/streams",
            metadata.GetProperty("configuration_endpoint").GetString());
        // Both push and poll delivery methods are advertised when stream mgmt is on.
        var delivery = metadata.GetProperty("delivery_methods_supported")
            .EnumerateArray().Select(d => d.GetString()).ToArray();
        Assert.Contains("urn:ietf:rfc:8935", delivery);
        Assert.Contains("urn:ietf:rfc:8934", delivery);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Ssf_stream_store_round_trips_create_get_and_disable()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ISsfStreamStore>();

            var stream = await store.CreateAsync(
                ownerClientId: "receiver-client",
                audience: "https://receiver.tests.local/events",
                deliveryMethod: SsfStreamStore.PollDeliveryMethod,
                endpoint: null,
                authorization: null,
                subjectScope: "ALL",
                eventsRequested: [CaepEventGenerator.SessionRevokedEventType],
                description: "test-poll",
                verificationChallenge: "test-verification-state",
                verificationExpiresAtUtc: DateTime.UtcNow.AddHours(1),
                CancellationToken.None);

            Assert.Equal("enabled", stream.Status);
            Assert.Equal("pending", stream.VerificationState);

            // Poll delivery enqueues a SET payload.
            var set = generator.GenerateSessionRevoked(
                "user-1", null, stream.Audience);
            await store.EnqueuePollDeliveryAsync(stream.StreamId, "jti-1", set, CancellationToken.None);

            var (payloads, more) = await store.PullAndConsumeAsync(stream.StreamId, 10, CancellationToken.None);
            Assert.Single(payloads);
            Assert.False(more);

            // Second pull returns nothing (consumed).
            var (empty, _) = await store.PullAndConsumeAsync(stream.StreamId, 10, CancellationToken.None);
            Assert.Empty(empty);

            await store.DisableForOwnerAsync(
                "receiver-client", stream.StreamId, CancellationToken.None);
            var after = await store.GetByStreamIdAsync(stream.StreamId, CancellationToken.None);
            Assert.Equal("disabled", after!.Status);
        }
    }

    [Fact]
    public async Task Verification_SET_carries_opaque_state_for_stream_handshake()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateVerification(
            "https://receiver.tests.local/events",
            "opaque-state-token");
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var verify = events.GetProperty(CaepEventGenerator.VerificationEventType);
        Assert.True(verify.GetProperty("event_timestamp").GetInt64() > 0);
        Assert.Equal("opaque-state-token",
            verify.GetProperty("state").GetString());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Poll_stream_enqueues_and_consumes_via_dispatcher_and_store()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ISsfStreamStore>();
            var dispatcher = scope.ServiceProvider
                .GetRequiredService<ISharedSignalsDispatcher>();

            var stream = await store.CreateAsync(
                ownerClientId: "receiver-client",
                audience: "https://receiver.tests.local/events",
                deliveryMethod: SsfStreamStore.PollDeliveryMethod,
                endpoint: null,
                authorization: null,
                subjectScope: "ALL",
                eventsRequested: [CaepEventGenerator.SessionRevokedEventType],
                description: null,
                verificationChallenge: "test-verification-state",
                verificationExpiresAtUtc: DateTime.UtcNow.AddHours(1),
                CancellationToken.None);

            Assert.Equal(
                SsfVerificationResult.Verified,
                await store.VerifyAsync(
                    "receiver-client",
                    stream.StreamId,
                    "test-verification-state",
                    CancellationToken.None));

            // Dispatching a session-revoked should enqueue into the poll queue
            // (no push endpoint), not throw.
            await dispatcher.SessionRevokedAsync(
                "user-1", null, CancellationToken.None);

            var (payloads, _) = await store.PullAndConsumeAsync(
                stream.StreamId, 10, CancellationToken.None);
            Assert.NotEmpty(payloads);

            // Second pull is empty (consumed).
            var (empty, _) = await store.PullAndConsumeAsync(
                stream.StreamId, 10, CancellationToken.None);
            Assert.Empty(empty);
        }
    }

    [Fact]
    public async Task Stream_store_enforces_owner_and_verification_challenge()
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ISsfStreamStore>();
            var stream = await store.CreateAsync(
                ownerClientId: "owner-a",
                audience: "receiver-a",
                deliveryMethod: SsfStreamStore.PollDeliveryMethod,
                endpoint: null,
                authorization: null,
                subjectScope: "ALL",
                eventsRequested: [],
                description: null,
                verificationChallenge: "correct-state",
                verificationExpiresAtUtc: DateTime.UtcNow.AddHours(1),
                CancellationToken.None);

            Assert.NotNull(await store.GetByStreamIdForOwnerAsync(
                "owner-a", stream.StreamId, CancellationToken.None));
            Assert.Null(await store.GetByStreamIdForOwnerAsync(
                "owner-b", stream.StreamId, CancellationToken.None));
            Assert.Empty(await store.ListEnabledPollAsync(CancellationToken.None));

            Assert.Equal(
                SsfVerificationResult.InvalidChallenge,
                await store.VerifyAsync(
                    "owner-a", stream.StreamId, "wrong-state", CancellationToken.None));
            Assert.Equal(
                SsfVerificationResult.NotFound,
                await store.VerifyAsync(
                    "owner-b", stream.StreamId, "correct-state", CancellationToken.None));
            Assert.Equal(
                SsfVerificationResult.Verified,
                await store.VerifyAsync(
                    "owner-a", stream.StreamId, "correct-state", CancellationToken.None));
            Assert.Single(await store.ListEnabledPollAsync(CancellationToken.None));
        }
    }

    [Fact]
    public async Task Dispatcher_applies_subject_and_event_filters_to_dynamic_streams()
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (factory)
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ISsfStreamStore>();
            var dispatcher = scope.ServiceProvider.GetRequiredService<ISharedSignalsDispatcher>();

            async Task<SsfStream> CreateVerifiedAsync(
                string owner, string subject, string eventType)
            {
                var stream = await store.CreateAsync(
                    ownerClientId: owner,
                    audience: owner,
                    deliveryMethod: SsfStreamStore.PollDeliveryMethod,
                    endpoint: null,
                    authorization: null,
                    subjectScope: subject,
                    eventsRequested: [eventType],
                    description: null,
                    verificationChallenge: "state-" + owner,
                    verificationExpiresAtUtc: DateTime.UtcNow.AddHours(1),
                    CancellationToken.None);
                Assert.Equal(
                    SsfVerificationResult.Verified,
                    await store.VerifyAsync(
                        owner, stream.StreamId, "state-" + owner, CancellationToken.None));
                return stream;
            }

            var matching = await CreateVerifiedAsync(
                "matching", "[\"user-1\"]", CaepEventGenerator.SessionRevokedEventType);
            var wrongSubject = await CreateVerifiedAsync(
                "wrong-subject", "[\"user-2\"]", CaepEventGenerator.SessionRevokedEventType);
            var wrongEvent = await CreateVerifiedAsync(
                "wrong-event", "[\"user-1\"]", CaepEventGenerator.CredentialChangeEventType);

            await dispatcher.SessionRevokedAsync("user-1", null, CancellationToken.None);

            Assert.Single((await store.PullAndConsumeAsync(
                matching.StreamId, 10, CancellationToken.None)).Payloads);
            Assert.Empty((await store.PullAndConsumeAsync(
                wrongSubject.StreamId, 10, CancellationToken.None)).Payloads);
            Assert.Empty((await store.PullAndConsumeAsync(
                wrongEvent.StreamId, 10, CancellationToken.None)).Payloads);
        }
    }
}
