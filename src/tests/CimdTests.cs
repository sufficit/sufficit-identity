using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Cimd;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A10 (eval 2026-08-14): Client ID Metadata Documents
/// (draft-ietf-oauth-client-id-metadata-document-02) — the registration
/// mechanism the MCP authorization spec adopted in place of DCR. The
/// client_id IS an HTTPS URL serving its metadata document directly; the STS
/// fetches it on first use and provisions a public PKCE client. These tests
/// pin the draft's enforcement rules and the provisioning defaults.
/// </summary>
public sealed class CimdTests
{
    private const string Identifier = "https://client.example/mcp-app";

    private static string Document(
        string clientId = Identifier,
        string? redirect = "https://client.example/callback",
        string? grantTypes = null,
        string? scope = null,
        string? authMethod = null,
        string? clientName = "MCP Client")
    {
        // Absent members are omitted (an explicit JSON null is a different
        // document than a missing member).
        var values = new Dictionary<string, object?>
        {
            ["client_id"] = clientId,
            ["client_name"] = clientName,
            ["redirect_uris"] = redirect is null
                ? Array.Empty<string>()
                : new[] { redirect },
        };
        if (grantTypes is not null)
        {
            values["grant_types"] = grantTypes.Split(',');
        }
        if (scope is not null)
        {
            values["scope"] = scope;
        }
        if (authMethod is not null)
        {
            values["token_endpoint_auth_method"] = authMethod;
        }
        return JsonSerializer.Serialize(values);
    }

    private static ClientIdMetadataResolver CreateResolver(
        Func<HttpRequestMessage, HttpResponseMessage> handler,
        ClientIdMetadataDocumentOptions? options = null)
    {
        var factory = new StubHttpClientFactory(
            new HttpClient(new StubHandler(handler)));
        return new ClientIdMetadataResolver(
            factory,
            options ?? new ClientIdMetadataDocumentOptions(),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<ClientIdMetadataResolver>.Instance);
    }

    [Fact]
    public async Task Valid_document_resolves_with_normalized_metadata()
    {
        var resolver = CreateResolver(
            request => Response(Document(
                grantTypes: "authorization_code,refresh_token",
                scope: "openid profile")));

        var document = await resolver.ResolveAsync(Identifier);

        Assert.NotNull(document);
        Assert.Equal(Identifier, document!.ClientId);
        Assert.Equal("MCP Client", document.ClientName);
        Assert.Equal(["https://client.example/callback"], document.RedirectUris);
        Assert.Equal(
            ["authorization_code", "refresh_token"],
            document.GrantTypes);
        Assert.Equal(["openid", "profile"], document.Scopes);
        // The fetch targets the identifier URL itself (no well-known path).
        Assert.Equal(Identifier, StubHandler.LastUrl);
    }

    [Theory]
    [InlineData("http://client.example/app")]          // not HTTPS
    [InlineData("https://user@client.example/app")]    // userinfo
    [InlineData("https://client.example/app?x=1")]     // query
    [InlineData("https://client.example/app#frag")]    // fragment
    [InlineData("https://client.example/a/../b")]      // dot segment
    [InlineData("not-a-url")]
    public async Task Invalid_identifier_shapes_never_fetch(
        string clientId)
    {
        var fetched = false;
        var resolver = CreateResolver(_ =>
        {
            fetched = true;
            return Response(Document());
        });

        Assert.Null(await resolver.ResolveAsync(clientId));
        Assert.False(fetched);
    }

    [Fact]
    public async Task Document_client_id_must_match_exactly()
    {
        var resolver = CreateResolver(
            _ => Response(Document(clientId: "https://other.example/app")));

        Assert.Null(await resolver.ResolveAsync(Identifier));
    }

    [Fact]
    public async Task Shared_secret_material_is_rejected()
    {
        var json = JsonSerializer.Serialize(
            new Dictionary<string, object?>
            {
                ["client_id"] = Identifier,
                ["client_secret"] = "super-secret",
                ["redirect_uris"] = new[] { "https://client.example/cb" },
            });
        var resolver = CreateResolver(_ => Response(json));

        Assert.Null(await resolver.ResolveAsync(Identifier));
    }

    [Theory]
    [InlineData("client_secret_basic")]
    [InlineData("client_secret_post")]
    [InlineData("client_secret_jwt")]
    [InlineData("private_key_jwt")]
    public async Task Non_public_auth_methods_are_rejected(string method)
    {
        var resolver = CreateResolver(
            _ => Response(Document(authMethod: method)));

        Assert.Null(await resolver.ResolveAsync(Identifier));
    }

    [Fact]
    public async Task Non_200_statuses_and_redirects_are_rejected()
    {
        // 3xx must NOT be followed (the draft forbids redirects; the HTTP
        // client is registered with AllowAutoRedirect=false — a redirect
        // surfaces as a non-200 here).
        foreach (var status in new[] { HttpStatusCode.Redirect,
                     HttpStatusCode.NotFound,
                     HttpStatusCode.InternalServerError })
        {
            var resolver = CreateResolver(_ => new HttpResponseMessage(status));
            Assert.Null(await resolver.ResolveAsync(Identifier));
        }
    }

    [Fact]
    public async Task Oversized_documents_are_rejected_without_parsing()
    {
        var resolver = CreateResolver(
            _ => Response("{\"client_id\":\"" + Identifier + "\",\"pad\":\"" +
                new string('x', 6000) + "\"}"),
            new ClientIdMetadataDocumentOptions());

        Assert.Null(await resolver.ResolveAsync(Identifier));
    }

    [Theory]
    [InlineData("http://client.example/cb", false)]   // non-https, non-loopback
    [InlineData("https://evil.example/cb", true)]     // any https host is fine
    [InlineData("http://127.0.0.1:8123/cb", true)]    // loopback exception
    [InlineData("https://client.example/cb#f", false)]
    public async Task Redirect_uris_follow_the_sts_wide_policy(
        string redirect,
        bool expected)
    {
        var resolver = CreateResolver(_ => Response(Document(redirect: redirect)));

        var document = await resolver.ResolveAsync(Identifier);

        if (expected)
        {
            Assert.NotNull(document);
        }
        else
        {
            Assert.Null(document);
        }
    }

    [Fact]
    public async Task Authorization_code_without_redirects_is_rejected()
    {
        var resolver = CreateResolver(
            _ => Response(Document(redirect: null)));

        Assert.Null(await resolver.ResolveAsync(Identifier));
    }

    [Fact]
    public async Task Failed_fetches_are_not_cached()
    {
        var attempts = 0;
        var resolver = CreateResolver(_ =>
        {
            attempts++;
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        Assert.Null(await resolver.ResolveAsync(Identifier));
        Assert.Null(await resolver.ResolveAsync(Identifier));
        Assert.Equal(2, attempts);
    }

    [Fact]
    public async Task Successful_documents_are_cached_for_the_ttl()
    {
        var attempts = 0;
        var resolver = CreateResolver(_ =>
        {
            attempts++;
            return Response(Document());
        });

        Assert.NotNull(await resolver.ResolveAsync(Identifier));
        Assert.NotNull(await resolver.ResolveAsync(Identifier));
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task Provisioner_creates_a_public_pkce_client_on_first_use()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mcp:ClientIdMetadataDocuments:Enabled"] =
                    "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var resolver = CreateResolver(_ => Response(Document(
            grantTypes: "authorization_code,refresh_token",
            scope: "openid profile offline_access")));
        await using var scope = factory.Services.CreateAsyncScope();
        var provisioner = new CimdApplicationProvisioner(
            scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>(),
            resolver,
            scope.ServiceProvider.GetRequiredService<SufficitIdentityOptions>(),
            NullLogger<CimdApplicationProvisioner>.Instance);

        var created = await provisioner.TryProvisionAsync(Identifier);
        Assert.NotNull(created);

        var applications =
            scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var byId = await applications.FindByClientIdAsync(Identifier);
        Assert.NotNull(byId);

        Assert.Equal(
            ConsentTypes.Explicit,
            await applications.GetConsentTypeAsync(byId));
        Assert.Equal(
            ClientTypes.Public,
            await applications.GetClientTypeAsync(byId));
        var permissions = await applications.GetPermissionsAsync(byId);
        Assert.Contains(Permissions.GrantTypes.AuthorizationCode, permissions);
        Assert.Contains(Permissions.GrantTypes.RefreshToken, permissions);
        Assert.Contains(Permissions.Endpoints.Authorization, permissions);
        Assert.Contains(Permissions.Endpoints.Token, permissions);
        Assert.Contains(Permissions.Prefixes.Scope + "openid", permissions);
        var requirements = await applications.GetRequirementsAsync(byId);
        Assert.Contains(
            Requirements.Features.ProofKeyForCodeExchange,
            requirements);

        // Idempotent: the second call returns the existing row.
        Assert.Equal(
            byId,
            await provisioner.TryProvisionAsync(Identifier));
    }

    private static HttpResponseMessage Response(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class StubHandler(
        Func<HttpRequestMessage, HttpResponseMessage> handler)
        : HttpMessageHandler
    {
        public static string? LastUrl { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastUrl = request.RequestUri?.AbsoluteUri;
            return Task.FromResult(handler(request));
        }
    }

    private sealed class StubHttpClientFactory(HttpClient client)
        : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
