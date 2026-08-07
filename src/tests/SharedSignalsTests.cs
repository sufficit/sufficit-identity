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

public sealed class SharedSignalsTests
{
    [Fact]
    public async Task Session_revoked_SET_has_the_required_SSF_CAEP_shape()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateSessionRevoked(
            "user-123", "session-456", "https://receiver.tests.local/events");
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "https://receiver.tests.local/events",
                IssuerSigningKey = new ECDsaSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                // SSF forbids exp, so receivers validate freshness/replay via
                // iat + jti according to their stream policy instead.
                ValidateLifetime = false,
            });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.Equal("secevent+jwt", jwt.Typ);
        Assert.Equal("https://sts.tests.local/", jwt.Issuer);
        Assert.Equal("https://receiver.tests.local/events", jwt.Audiences.Single());
        Assert.True(jwt.TryGetPayloadValue("iat", out long _));
        Assert.True(jwt.TryGetPayloadValue("jti", out string _));
        Assert.True(jwt.TryGetPayloadValue("txn", out string _));
        Assert.False(jwt.TryGetPayloadValue("sub", out string _));
        Assert.False(jwt.TryGetPayloadValue("exp", out long _));

        Assert.True(jwt.TryGetPayloadValue("sub_id", out JsonElement subId));
        Assert.Equal("complex", subId.GetProperty("format").GetString());
        Assert.Equal("user-123",
            subId.GetProperty("user").GetProperty("sub").GetString());
        Assert.Equal("session-456",
            subId.GetProperty("session").GetProperty("id").GetString());

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var revoked = events.GetProperty(CaepEventGenerator.SessionRevokedEventType);
        Assert.True(revoked.GetProperty("event_timestamp").GetInt64() > 0);
    }

    [Fact]
    public async Task SSF_discovery_is_exposed_only_when_the_transmitter_is_enabled()
    {
        using var disabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)disabled).InitializeAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await disabled.CreateClient().GetAsync(
                "/.well-known/ssf-configuration")).StatusCode);

        using var enabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)enabled).InitializeAsync();
        using var response = await enabled.CreateClient().GetAsync(
            "/.well-known/ssf-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json",
            response.Content.Headers.ContentType?.MediaType);
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("1_0", metadata.GetProperty("spec_version").GetString());
        Assert.Equal("https://sts.tests.local/",
            metadata.GetProperty("issuer").GetString());
        Assert.Equal("urn:ietf:rfc:8935",
            metadata.GetProperty("delivery_methods_supported")[0].GetString());
        Assert.False(metadata.TryGetProperty("configuration_endpoint", out _));
    }

    [Fact]
    public async Task Push_dispatcher_posts_an_authenticated_signed_SET()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");
        var options = new SharedSignalsOptions
        {
            Enabled = true,
            Receivers =
            {
                new SharedSignalsReceiverOptions
                {
                    Id = "receiver-a",
                    Audience = "https://receiver.tests.local/events",
                    Endpoint = "https://receiver.tests.local/push",
                    Authorization = "Bearer test-secret",
                },
            },
        };
        var capture = new CaptureHandler();
        var dispatcher = new SharedSignalsPushDispatcher(
            generator,
            options,
            new HttpClient(capture),
            NullLogger<SharedSignalsPushDispatcher>.Instance);

        await dispatcher.SessionRevokedAsync(
            "user-123", "session-456", CancellationToken.None);

        Assert.Equal("https://receiver.tests.local/push",
            capture.RequestUri?.AbsoluteUri);
        Assert.Equal("application/secevent+jwt", capture.ContentType);
        Assert.Equal("Bearer test-secret", capture.Authorization);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(capture.Body!);
        Assert.Equal("https://receiver.tests.local/events", jwt.Audiences.Single());
        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        Assert.True(events.TryGetProperty(
            CaepEventGenerator.SessionRevokedEventType, out _));
    }

    [Fact]
    public async Task Credential_change_SET_carries_change_type_and_credential_type()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateCredentialChange(
            "user-123",
            sessionId: null,
            "https://receiver.tests.local/events",
            new CaepCredentialChange(
                CaepCredentialType.Federated,
                CaepChangeOperation.Created,
                FederatedType: "GitHub"));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.Equal("secevent+jwt", jwt.Typ);
        Assert.False(jwt.TryGetPayloadValue("exp", out long _));
        Assert.True(jwt.TryGetPayloadValue("sub_id", out JsonElement subId));
        // No session → iss_sub (not complex) format.
        Assert.Equal("iss_sub", subId.GetProperty("format").GetString());
        Assert.Equal("user-123", subId.GetProperty("sub").GetString());

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var change = events.GetProperty(CaepEventGenerator.CredentialChangeEventType);
        Assert.True(change.GetProperty("event_timestamp").GetInt64() > 0);
        Assert.Equal("create", change.GetProperty("change_type").GetString());
        Assert.Equal("federated", change.GetProperty("credential_type").GetString());
        Assert.Equal("GitHub", change.GetProperty("federated_type").GetString());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Device_change_SET_carries_change_type_and_credential_id()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateDeviceChange(
            "user-123",
            "session-456",
            "https://receiver.tests.local/events",
            new CaepDeviceChange(
                CaepChangeOperation.Created,
                CredentialId: "passkey-abc",
                Description: "YubiKey 5C"));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var change = events.GetProperty(CaepEventGenerator.DeviceChangeEventType);
        Assert.Equal("create", change.GetProperty("change_type").GetString());
        Assert.Equal("passkey-abc", change.GetProperty("credential_id").GetString());
        Assert.Equal("YubiKey 5C", change.GetProperty("description").GetString());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Push_dispatcher_posts_a_credential_change_SET()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");
        var options = new SharedSignalsOptions
        {
            Enabled = true,
            Receivers =
            {
                new SharedSignalsReceiverOptions
                {
                    Id = "receiver-a",
                    Audience = "https://receiver.tests.local/events",
                    Endpoint = "https://receiver.tests.local/push",
                    Authorization = "Bearer test-secret",
                },
            },
        };
        var capture = new CaptureHandler();
        var dispatcher = new SharedSignalsPushDispatcher(
            generator,
            options,
            new HttpClient(capture),
            NullLogger<SharedSignalsPushDispatcher>.Instance);

        await dispatcher.CredentialChangedAsync(
            "user-123",
            sessionId: null,
            new CaepCredentialChange(
                CaepCredentialType.Password,
                CaepChangeOperation.Updated),
            CancellationToken.None);

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(capture.Body!);
        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        Assert.True(events.TryGetProperty(
            CaepEventGenerator.CredentialChangeEventType, out var change));
        Assert.Equal("update", change.GetProperty("change_type").GetString());
        Assert.Equal("password", change.GetProperty("credential_type").GetString());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Security_event_trigger_adapter_fires_credential_change_with_session_id()
    {
        // The adapter must extract the `sid` claim from the principal and pass
        // it through so the SET carries session-specific subject identifiers.
        var captured = new CapturingTrigger();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim("sid", "session-789") },
            authenticationType: "Test"));

        await ((ISecurityEventTrigger)captured).CredentialChangedAsync(
            principal,
            "user-123",
            new CaepCredentialChange(
                CaepCredentialType.Password,
                CaepChangeOperation.Updated),
            CancellationToken.None);

        Assert.NotNull(captured.LastCredentialChange);
        Assert.Equal(CaepCredentialType.Password,
            captured.LastCredentialChange!.CredentialType);
        Assert.Equal("session-789", captured.LastSessionId);
        Assert.Equal("user-123", captured.LastSubject);
    }

    [Fact]
    public async Task Discovery_advertises_events_supported_when_enabled()
    {
        using var enabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)enabled).InitializeAsync();
        using var response = await enabled.CreateClient().GetAsync(
            "/.well-known/ssf-configuration");
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(metadata.TryGetProperty("events_supported", out var events));
        var supported = events.EnumerateArray()
            .Select(item => item.GetString())
            .ToArray();
        Assert.Contains(CaepEventGenerator.SessionRevokedEventType, supported);
        Assert.Contains(CaepEventGenerator.CredentialChangeEventType, supported);
        Assert.Contains(CaepEventGenerator.DeviceChangeEventType, supported);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Subject_identifier_email_format_round_trips()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateSessionRevoked(
            CaepSubjectIdentifier.Email("alice@example.com"),
            "https://receiver.tests.local/events");
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.True(jwt.TryGetPayloadValue("sub_id", out JsonElement subId));
        Assert.Equal("email", subId.GetProperty("format").GetString());
        Assert.Equal("alice@example.com",
            subId.GetProperty("email").GetString());
        // Issuer is filled in by the transmitter (null on the factory → STS issuer).
        Assert.Equal("https://sts.tests.local/",
            subId.GetProperty("iss").GetString());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Assurance_level_change_SET_carries_current_and_previous_levels()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateAssuranceLevelChange(
            "user-123",
            sessionId: null,
            "https://receiver.tests.local/events",
            new CaepAssuranceLevelChange(
                CurrentLevel: CaepAssuranceLevel.Loa2,
                PreviousLevel: CaepAssuranceLevel.Loa1));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var level = events.GetProperty(CaepEventGenerator.AssuranceLevelChangeEventType);
        Assert.True(level.GetProperty("event_timestamp").GetInt64() > 0);
        Assert.Equal("loa2", level.GetProperty("current_level").GetString());
        Assert.Equal("normal", level.GetProperty("previous_level").GetString());
        Assert.Equal("loa2", level.GetProperty("current_loa").GetString());
        Assert.Equal("loa1", level.GetProperty("previous_loa").GetString());
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData(new[] { "pwd" }, CaepAssuranceLevel.Loa1)]
    [InlineData(new[] { "pwd", "otp" }, CaepAssuranceLevel.Loa2)]
    [InlineData(new[] { "pwd", "hwk" }, CaepAssuranceLevel.PhishingResistant)]
    [InlineData(new[] { "passkey" }, CaepAssuranceLevel.PhishingResistant)]
    [InlineData(new[] { "fido" }, CaepAssuranceLevel.PhishingResistant)]
    [InlineData(new string[0], CaepAssuranceLevel.Loa1)]
    public async Task Amr_resolver_maps_factors_to_assurance_level(
        string[] amrs,
        CaepAssuranceLevel expected)
    {
        var resolver = new AmrBasedAssuranceLevelResolver();
        var identity = new ClaimsIdentity(
            amrs.Select(amr => new Claim("amr", amr)),
            authenticationType: "Test");
        var principal = new ClaimsPrincipal(identity);

        Assert.Equal(expected, resolver.Resolve(principal));
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData(CaepAssuranceLevel.Loa1, CaepAssuranceLevel.Loa2)]
    [InlineData(CaepAssuranceLevel.Loa1, CaepAssuranceLevel.PhishingResistant)]
    public async Task Amr_resolver_reads_stamped_aal_claim_first(
        CaepAssuranceLevel stamped,
        CaepAssuranceLevel _)
    {
        // When the session already carries an `aal` claim (stamped by the
        // principal factory), the resolver must prefer it over re-deriving
        // from amr — so a cookie from before a step-up still reports the
        // old level even if the amr claims would imply a higher one.
        var resolver = new AmrBasedAssuranceLevelResolver();
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim("aal", stamped.ToString()),
                new Claim("amr", "passkey"),
            },
            authenticationType: "Test");
        var principal = new ClaimsPrincipal(identity);

        Assert.Equal(stamped, resolver.Resolve(principal));
        await Task.CompletedTask;
    }

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
                eventsRequested: [],
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

    /// <summary>
    /// Stub <see cref="ISecurityEventTrigger"/> that records the last call so
    /// trigger-wiring tests can assert what was fired without a real HTTP
    /// receiver.
    /// </summary>
    private sealed class CapturingTrigger : ISecurityEventTrigger
    {
        public string? LastSubject { get; private set; }
        public string? LastSessionId { get; private set; }
        public CaepCredentialChange? LastCredentialChange { get; private set; }
        public CaepDeviceChange? LastDeviceChange { get; private set; }
        public CaepAssuranceLevelChange? LastAssuranceLevelChange { get; private set; }

        public Task CredentialChangedAsync(
            string subject,
            string? sessionId,
            CaepCredentialChange change,
            CancellationToken cancellationToken = default)
        {
            LastSubject = subject;
            LastSessionId = sessionId;
            LastCredentialChange = change;
            return Task.CompletedTask;
        }

        public Task DeviceChangedAsync(
            string subject,
            string? sessionId,
            CaepDeviceChange change,
            CancellationToken cancellationToken = default)
        {
            LastSubject = subject;
            LastSessionId = sessionId;
            LastDeviceChange = change;
            return Task.CompletedTask;
        }

        public Task AssuranceLevelChangedAsync(
            string subject,
            string? sessionId,
            CaepAssuranceLevelChange change,
            CancellationToken cancellationToken = default)
        {
            LastSubject = subject;
            LastSessionId = sessionId;
            LastAssuranceLevelChange = change;
            return Task.CompletedTask;
        }
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        public string? ContentType { get; private set; }
        public string? Authorization { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            ContentType = request.Content?.Headers.ContentType?.MediaType;
            Authorization = request.Headers.GetValues("Authorization").Single();
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }
}
