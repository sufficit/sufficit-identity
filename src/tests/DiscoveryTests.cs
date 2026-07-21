using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class DiscoveryTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public DiscoveryTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Discovery_document_does_not_advertise_unimplemented_logout_capabilities()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();

        // #N3 fix: back/front-channel logout distribution is NOT implemented
        // (AuthorizationController.BackchannelLogout/FrontchannelLogout are
        // unadvertised no-op ack stubs; real RP fan-out is Onda B). Discovery
        // must publish all four flags as explicit `false` so OIDC clients
        // natively skip the flows instead of probing.
        Assert.False(json.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.False(json.GetProperty("backchannel_logout_session_supported").GetBoolean());
        Assert.False(json.GetProperty("frontchannel_logout_supported").GetBoolean());
        Assert.False(json.GetProperty("frontchannel_logout_session_supported").GetBoolean());

        // OpenIddict's own base discovery handler (not Sufficit's customization)
        // always emits these two as honest `false` booleans — that's not a
        // capability claim, it's the framework being explicit that neither
        // feature is supported. Verified against the actual response before
        // asserting: OpenIddict 7.6's discovery document really does include
        // both, always with a `false` value, regardless of the custom
        // HandleConfigurationRequestContext handler in
        // ServiceCollectionExtensions.cs (which only adds the logout flags).
        Assert.False(json.GetProperty("claims_parameter_supported").GetBoolean());
        Assert.False(json.GetProperty("request_parameter_supported").GetBoolean());

        foreach (var honestlyAbsentKey in new[]
        {
            // DPoP and the check_session_iframe (session-management draft) are
            // not implemented and OpenIddict never emits them unprompted.
            "dpop_signing_alg_values_supported",
            "check_session_iframe",
            // Per-client registration metadata, not OP discovery metadata —
            // deliberately never surfaced here (see the comment above
            // AddEventHandler<HandleConfigurationRequestContext> in
            // src/server/ServiceCollectionExtensions.cs).
            "backchannel_logout_url",
        })
        {
            Assert.False(
                json.TryGetProperty(honestlyAbsentKey, out _),
                $"Discovery document unexpectedly advertises '{honestlyAbsentKey}', which is not implemented.");
        }
    }
}
