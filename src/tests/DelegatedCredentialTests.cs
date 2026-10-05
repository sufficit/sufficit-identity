using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Delegated device credentials: a trusted client exchanges a fresh user
/// token (RFC 8693) for a refresh token of another client, bound to the DPoP
/// key of the device that will use it (RFC 9449).
/// </summary>
public sealed class DelegatedCredentialTests
{
    private const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    private const string RefreshTokenType = "urn:ietf:params:oauth:token-type:refresh_token";

    private const string DelegatorClientId = "test-delegator";
    private const string DelegatorClientSecret = "test-delegator-secret";
    private const string OtherCallerClientId = "test-delegator-unlisted";
    private const string OtherCallerClientSecret = "test-delegator-unlisted-secret";
    private const string DelegateClientId = "test-device-delegate";
    private const string DelegationScope = "test.delegate";
    private const string PrivateScope = "test.private";
    private const string Password = "Deleg4te!Passw0rd#9";

    [Fact]
    public async Task Delegated_credential_refreshes_only_with_the_bound_key()
    {
        await using var env = await DelegationEnvironment.CreateAsync();
        var user = await env.CreateUserAsync();
        var deviceKey = NewKey();
        var label = Guid.NewGuid().ToString();

        var (status, body) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(deviceKey), label);

        Assert.True(status == HttpStatusCode.OK, body.ToString());
        Assert.Equal(RefreshTokenType, body.GetProperty("issued_token_type").GetString());
        Assert.False(body.TryGetProperty("refresh_token", out _));
        var credential = body.GetProperty("access_token").GetString()!;
        Assert.InRange(body.GetProperty("expires_in").GetInt64(),
            TimeSpan.FromDays(30).TotalSeconds - 120, TimeSpan.FromDays(30).TotalSeconds);

        // The caller cannot use it, nor can a device without the key.
        var (callerStatus, _) = await env.RefreshAsync(credential, DelegatorClientId, deviceKey,
            DelegatorClientSecret);
        Assert.Equal(HttpStatusCode.BadRequest, callerStatus);
        var (wrongKeyStatus, wrongKeyBody) = await env.RefreshAsync(credential, DelegateClientId, NewKey());
        Assert.Equal(HttpStatusCode.BadRequest, wrongKeyStatus);
        Assert.Equal("invalid_grant", wrongKeyBody.GetProperty("error").GetString());
        var (noProofStatus, _) = await env.RefreshAsync(credential, DelegateClientId, null);
        Assert.Equal(HttpStatusCode.BadRequest, noProofStatus);

        var (refreshStatus, refreshed) = await env.RefreshAsync(credential, DelegateClientId, deviceKey);
        Assert.True(refreshStatus == HttpStatusCode.OK, refreshed.ToString());
        Assert.Equal("DPoP", refreshed.GetProperty("token_type").GetString());
        var rotated = refreshed.GetProperty("refresh_token").GetString()!;

        var introspection = await env.IntrospectAsync(refreshed.GetProperty("access_token").GetString()!);
        Assert.Equal(user.Id, introspection.GetProperty("sub").GetString());
        Assert.Equal(DelegateClientId, introspection.GetProperty("client_id").GetString());
        Assert.Equal(Thumbprint(deviceKey),
            introspection.GetProperty("cnf").GetProperty("jkt").GetString());
        Assert.Equal(DelegatorClientId,
            introspection.GetProperty("act").GetProperty("sub").GetString());
        var scopes = introspection.GetProperty("scope").GetString()!.Split(' ');
        Assert.Contains(TestDataSeeder.ScopeName, scopes);
        Assert.DoesNotContain(DelegationScope, scopes);
        Assert.DoesNotContain(PrivateScope, scopes);
        Assert.False(introspection.TryGetProperty(DelegatedCredential.ExpiresAtClaimType, out _));

        // The rotated refresh token is still the delegated credential.
        var (secondStatus, second) = await env.RefreshAsync(rotated, DelegateClientId, deviceKey);
        Assert.True(secondStatus == HttpStatusCode.OK, second.ToString());
        var secondIntrospection = await env.IntrospectAsync(second.GetProperty("access_token").GetString()!);
        Assert.Equal(DelegatorClientId,
            secondIntrospection.GetProperty("act").GetProperty("sub").GetString());

        // Audited (without token material) and announced to the user.
        var audits = await env.AuditsAsync();
        var issued = Assert.Single(audits, audit => audit.OperationOutcome == "issued");
        Assert.Equal(user.Id, issued.OperatorSubject);
        Assert.Contains(label, issued.AfterJson);
        Assert.DoesNotContain(credential, issued.AfterJson);
        Assert.DoesNotContain(Thumbprint(deviceKey), issued.AfterJson);
        var message = Assert.Single(env.Email.Messages, item => item.Email == user.Email);
        Assert.Contains(label, message.Body);
    }

    [Fact]
    public async Task Delegated_credential_never_outlives_its_absolute_deadline()
    {
        await using var env = await DelegationEnvironment.CreateAsync(new()
        {
            ["Sufficit:Identity:TokenExchange:DelegatedCredentials:CredentialLifetimeDays"] = "1",
        });
        var user = await env.CreateUserAsync();
        var key = NewKey();
        var (_, body) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(key), Guid.NewGuid().ToString());
        var deadline = DateTimeOffset.UtcNow.AddDays(1).AddMinutes(1);

        var (status, refreshed) = await env.RefreshAsync(
            body.GetProperty("access_token").GetString()!, DelegateClientId, key);
        Assert.True(status == HttpStatusCode.OK, refreshed.ToString());

        await using var scope = env.Host.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var expirations = await database.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Subject == user.Id)
            .Select(token => token.ExpirationDate)
            .ToListAsync();
        Assert.True(expirations.Count >= 3);
        Assert.All(expirations, expiration =>
            Assert.True(expiration is { } value
                && new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)) <= deadline,
                $"Token expires {expiration:o}, after the delegation deadline."));
    }

    [Fact]
    public async Task Delegating_the_same_label_again_revokes_the_previous_credential()
    {
        await using var env = await DelegationEnvironment.CreateAsync();
        var user = await env.CreateUserAsync();
        var label = Guid.NewGuid().ToString();
        var firstKey = NewKey();
        var secondKey = NewKey();

        var (_, first) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(firstKey), label);
        var (secondStatus, second) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(secondKey), label.ToUpperInvariant());
        Assert.Equal(HttpStatusCode.OK, secondStatus);

        var (oldStatus, _) = await env.RefreshAsync(
            first.GetProperty("access_token").GetString()!, DelegateClientId, firstKey);
        Assert.Equal(HttpStatusCode.BadRequest, oldStatus);
        var (newStatus, _) = await env.RefreshAsync(
            second.GetProperty("access_token").GetString()!, DelegateClientId, secondKey);
        Assert.Equal(HttpStatusCode.OK, newStatus);
    }

    [Fact]
    public async Task Active_credentials_per_user_are_capped_but_replacement_is_allowed()
    {
        await using var env = await DelegationEnvironment.CreateAsync(new()
        {
            ["Sufficit:Identity:TokenExchange:DelegatedCredentials:MaxActivePerUser"] = "2",
        });
        var user = await env.CreateUserAsync();
        var labels = new[] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString() };
        foreach (var label in labels)
        {
            var (status, _) = await env.ExchangeAsync(
                await env.SubjectTokenAsync(user.UserName!), Thumbprint(NewKey()), label);
            Assert.Equal(HttpStatusCode.OK, status);
        }

        var (capped, cappedBody) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(NewKey()), Guid.NewGuid().ToString());
        Assert.Equal(HttpStatusCode.BadRequest, capped);
        Assert.Equal("invalid_request", cappedBody.GetProperty("error").GetString());
        Assert.Contains("limit 2", cappedBody.GetProperty("error_description").GetString());

        var (replaced, _) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(NewKey()), labels[0]);
        Assert.Equal(HttpStatusCode.OK, replaced);
        Assert.Contains(await env.AuditsAsync(), audit => audit.ReasonCode == "cap_exceeded");
    }

    [Fact]
    public async Task Each_rule_refuses_with_a_specific_error()
    {
        await using var env = await DelegationEnvironment.CreateAsync();
        var user = await env.CreateUserAsync();
        var subjectToken = await env.SubjectTokenAsync(user.UserName!);
        var jkt = Thumbprint(NewKey());
        var label = Guid.NewGuid().ToString();

        async Task AssertRefusedAsync(
            string error,
            string? callerId = null,
            string? callerSecret = null,
            string? token = null,
            string? thumbprint = null,
            string? executorId = null,
            bool omitJkt = false,
            bool omitLabel = false)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = TokenExchangeGrant,
                ["client_id"] = callerId ?? DelegatorClientId,
                ["client_secret"] = callerSecret ?? DelegatorClientSecret,
                ["subject_token"] = token ?? subjectToken,
                ["subject_token_type"] = AccessTokenType,
                ["requested_token_type"] = RefreshTokenType,
                ["audience"] = DelegateClientId,
            };
            if (!omitJkt) form["dpop_jkt"] = thumbprint ?? jkt;
            if (!omitLabel) form["executor_id"] = executorId ?? label;
            var (status, body) = await env.Client.PostFormAsync("/connect/token", form);
            Assert.True(status == HttpStatusCode.BadRequest, body.ToString());
            Assert.Equal(error, body.GetProperty("error").GetString());
        }

        // A client outside the delegator allow-list, even with the grant
        // permission and its own user token.
        await AssertRefusedAsync(Errors.UnauthorizedClient, OtherCallerClientId, OtherCallerClientSecret,
            token: await env.SubjectTokenAsync(user.UserName!, OtherCallerClientId, OtherCallerClientSecret));
        // The subject token lacks the delegation scope.
        await AssertRefusedAsync(Errors.InvalidScope,
            token: await env.SubjectTokenAsync(user.UserName!, scope: TestDataSeeder.ScopeName));
        await AssertRefusedAsync(Errors.InvalidRequest, omitJkt: true);
        await AssertRefusedAsync(Errors.InvalidRequest, thumbprint: "not-a-thumbprint");
        await AssertRefusedAsync(Errors.InvalidRequest, thumbprint: jkt + "=");
        await AssertRefusedAsync(Errors.InvalidRequest, omitLabel: true);
        await AssertRefusedAsync(Errors.InvalidRequest, executorId: "device-1");

        // The account can no longer sign in.
        await using (var scope = env.Host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var stored = (await users.FindByIdAsync(user.Id))!;
            stored.EmailConfirmed = false;
            await users.UpdateAsync(stored);
        }

        await AssertRefusedAsync(Errors.InvalidGrant);

        var reasons = (await env.AuditsAsync())
            .Where(audit => audit.OperationOutcome == "refused")
            .Select(audit => audit.ReasonCode)
            .ToArray();
        Assert.Contains("caller_not_allowed", reasons);
        Assert.Contains("missing_delegation_scope", reasons);
        Assert.Contains("invalid_dpop_jkt", reasons);
        Assert.Contains("invalid_label", reasons);
        Assert.Contains("user_not_allowed", reasons);
        Assert.DoesNotContain(await env.AuditsAsync(), audit => audit.OperationOutcome == "issued");
    }

    [Fact]
    public async Task Refresh_token_requests_outside_the_delegation_contract_are_refused()
    {
        await using var env = await DelegationEnvironment.CreateAsync();
        var user = await env.CreateUserAsync();
        var (status, body) = await env.Client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["client_id"] = DelegatorClientId,
            ["client_secret"] = DelegatorClientSecret,
            ["subject_token"] = await env.SubjectTokenAsync(user.UserName!),
            ["subject_token_type"] = AccessTokenType,
            ["requested_token_type"] = RefreshTokenType,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(Errors.InvalidRequest, body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Disabled_feature_keeps_refusing_refresh_token_requests()
    {
        await using var env = await DelegationEnvironment.CreateAsync(new()
        {
            ["Sufficit:Identity:TokenExchange:DelegatedCredentials:Enabled"] = "false",
        });
        var user = await env.CreateUserAsync();
        var (status, body) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(NewKey()), Guid.NewGuid().ToString());

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(Errors.InvalidRequest, body.GetProperty("error").GetString());
        Assert.Contains("requested_token_type", body.GetProperty("error_description").GetString());
        Assert.Empty(await env.AuditsAsync());
    }

    [Fact]
    public async Task User_lists_and_revokes_a_delegated_credential()
    {
        await using var env = await DelegationEnvironment.CreateAsync();
        var user = await env.CreateUserAsync();
        var key = NewKey();
        var label = Guid.NewGuid().ToString();
        var (_, body) = await env.ExchangeAsync(
            await env.SubjectTokenAsync(user.UserName!), Thumbprint(key), label);

        await using (var scope = env.Host.Services.CreateAsyncScope())
        {
            var access = scope.ServiceProvider.GetRequiredService<IAccountAccessService>();
            var principal = AccountAccessServiceTests.PrincipalFor(user);
            var credential = Assert.Single(await access.GetDelegatedCredentialsAsync(principal));
            Assert.Equal(label, credential.Label);
            Assert.Equal(DelegateClientId, credential.ClientId);
            Assert.Equal(DelegatorClientId, credential.DelegatorClientId);
            Assert.True(credential.ExpiresAt > DateTimeOffset.UtcNow.AddDays(29));
            Assert.Contains(await access.GetConnectedApplicationsAsync(principal),
                application => application.ClientId == DelegateClientId);

            var stranger = await env.CreateUserAsync();
            Assert.False((await access.RevokeDelegatedCredentialAsync(
                AccountAccessServiceTests.PrincipalFor(stranger), credential.Id)).Succeeded);
            Assert.True((await access.RevokeDelegatedCredentialAsync(principal, credential.Id)).Succeeded);
            Assert.Empty(await access.GetDelegatedCredentialsAsync(principal));
        }

        var (status, _) = await env.RefreshAsync(
            body.GetProperty("access_token").GetString()!, DelegateClientId, key);
        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(11, true)]
    [InlineData(13, false)]
    [InlineData(-1, false)]
    public void Sign_in_age_is_bounded(int hoursAgo, bool expected)
    {
        var now = new DateTimeOffset(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(expected, DelegatedCredentialIssuer.IsRecent(now.AddHours(-hoursAgo), now, 12));
    }

    [Theory]
    [InlineData("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", true)]
    [InlineData("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs=", false)]
    [InlineData("NzbLsXh8uDCcd+6MNwXF4W/7noWXFZAfHkxZsRGC9Xs", false)]
    [InlineData("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Thumbprint_must_be_canonical_base64url_sha256(string? value, bool expected) =>
        Assert.Equal(expected, DelegatedCredential.IsValidThumbprint(value));

    [Fact]
    public void Posture_reports_unsafe_settings_only_while_enabled()
    {
        static string[] Findings(DelegatedCredentialOptions options) =>
            STS.Security.StsProductionPostureContributor
                .EvaluateDelegatedCredentials(new TokenExchangeOptions { DelegatedCredentials = options })
                .Select(finding => finding.Id)
                .ToArray();

        Assert.Empty(Findings(new DelegatedCredentialOptions
        {
            CredentialLifetimeDays = 365,
            NotifyOnIssue = false,
        }));
        Assert.Empty(Findings(new DelegatedCredentialOptions
        {
            Enabled = true,
            DelegatorClientIds = { "app" },
            DelegateClientId = "device",
            RequiredScope = "delegate",
        }));
        Assert.Equal(
            [
                "delegated-credentials-no-delegators",
                "delegated-credentials-long-lifetime",
                "delegated-credentials-stale-sign-in",
                "delegated-credentials-silent",
            ],
            Findings(new DelegatedCredentialOptions
            {
                Enabled = true,
                DelegateClientId = "device",
                RequiredScope = "delegate",
                CredentialLifetimeDays = 120,
                MaxAuthAgeHours = 48,
                NotifyOnIssue = false,
            }));
    }

    [Fact]
    public void Enabled_configuration_is_validated()
    {
        Assert.Empty(new DelegatedCredentialOptions { CredentialLifetimeDays = 0 }.Validate());
        var errors = new DelegatedCredentialOptions
        {
            Enabled = true,
            DelegatorClientIds = { "device" },
            DelegateClientId = "device",
            CredentialLifetimeDays = 0,
            MaxActivePerUser = 0,
            MaxAuthAgeHours = 0,
        }.Validate().ToArray();
        Assert.Equal(5, errors.Length);
    }

    [Fact]
    public async Task Enabling_without_dpop_refuses_startup()
    {
        var failure = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using var env = await DelegationEnvironment.CreateAsync(new()
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "false",
            });
        });
        Assert.Contains("Dpop:Enabled", failure.ToString());
    }

    private static ECDsaSecurityKey NewKey() =>
        new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    private static string Thumbprint(ECDsaSecurityKey key)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        return Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
    }

    private static string Proof(ECDsaSecurityKey key, string url)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var now = DateTimeOffset.UtcNow;
        return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(
            new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>
                {
                    ["htm"] = "POST",
                    ["htu"] = url,
                    ["iat"] = EpochTime.GetIntDate(now.UtcDateTime),
                    ["exp"] = EpochTime.GetIntDate(now.AddMinutes(1).UtcDateTime),
                    ["jti"] = Guid.NewGuid().ToString("N"),
                },
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["typ"] = DpopProofValidator.DpopHeaderType,
                    ["jwk"] = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(jwk)),
                },
            });
    }

    private sealed class DelegationEnvironment : IAsyncDisposable
    {
        private readonly SufficitIdentityTestFactory _factory;

        private DelegationEnvironment(
            SufficitIdentityTestFactory factory,
            WebApplicationFactory<SufficitIdentityTestFactory> host,
            RecordingEmailSender email)
        {
            _factory = factory;
            Host = host;
            Email = email;
            Client = host.CreateClient();
        }

        public WebApplicationFactory<SufficitIdentityTestFactory> Host { get; }

        public HttpClient Client { get; }

        public RecordingEmailSender Email { get; }

        public static async Task<DelegationEnvironment> CreateAsync(
            Dictionary<string, string?>? overrides = null)
        {
            var configuration = new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:TokenExchange:DelegatedCredentials:Enabled"] = "true",
                ["Sufficit:Identity:TokenExchange:DelegatedCredentials:DelegatorClientIds:0"] = DelegatorClientId,
                ["Sufficit:Identity:TokenExchange:DelegatedCredentials:DelegateClientId"] = DelegateClientId,
                ["Sufficit:Identity:TokenExchange:DelegatedCredentials:RequiredScope"] = DelegationScope,
            };
            foreach (var (key, value) in overrides ?? [])
            {
                configuration[key] = value;
            }

            var factory = SufficitIdentityTestFactory.CreateIsolated(configuration);
            try
            {
                await ((IAsyncLifetime)factory).InitializeAsync();
            }
            catch
            {
                factory.Dispose();
                throw;
            }

            var email = new RecordingEmailSender();
            var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
                services.Replace(ServiceDescriptor.Singleton<IEmailSender>(email))));
            await using (var scope = host.Services.CreateAsyncScope())
            {
                await SeedAsync(scope.ServiceProvider);
            }

            return new DelegationEnvironment(factory, host, email);
        }

        public async Task<ApplicationUser> CreateUserAsync()
        {
            await using var scope = Host.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            return await TestDataSeeder.CreateUserAsync(users, $"delegation-{Guid.NewGuid():N}", Password);
        }

        public async Task<string> SubjectTokenAsync(
            string username,
            string clientId = DelegatorClientId,
            string clientSecret = DelegatorClientSecret,
            string scope = TestDataSeeder.ScopeName + " " + DelegationScope + " " + PrivateScope)
        {
            var (status, body) = await Client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = Password,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = scope,
            });
            Assert.True(status == HttpStatusCode.OK, body.ToString());
            return body.GetProperty("access_token").GetString()!;
        }

        public Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(
            string subjectToken, string jkt, string label) =>
            Client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = TokenExchangeGrant,
                ["client_id"] = DelegatorClientId,
                ["client_secret"] = DelegatorClientSecret,
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = AccessTokenType,
                ["requested_token_type"] = RefreshTokenType,
                ["audience"] = DelegateClientId,
                ["dpop_jkt"] = jkt,
                ["executor_id"] = label,
            });

        public async Task<(HttpStatusCode Status, JsonElement Body)> RefreshAsync(
            string refreshToken,
            string clientId,
            ECDsaSecurityKey? key,
            string? clientSecret = null)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId,
            };
            if (clientSecret is not null)
            {
                form["client_secret"] = clientSecret;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Content = new FormUrlEncodedContent(form),
            };
            if (key is not null)
            {
                request.Headers.Add("DPoP",
                    Proof(key, new Uri(Client.BaseAddress!, "connect/token").AbsoluteUri));
            }

            using var response = await Client.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
            return (response.StatusCode, document.RootElement.Clone());
        }

        public async Task<JsonElement> IntrospectAsync(string token)
        {
            var client = Host.CreateClient();
            client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
                TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
            var (status, body) = await client.PostFormAsync("/connect/introspect",
                new Dictionary<string, string> { ["token"] = token });
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.True(body.GetProperty("active").GetBoolean(), body.ToString());
            return body;
        }

        public async Task<IReadOnlyList<ManagementAuditEvent>> AuditsAsync()
        {
            await using var scope = Host.Services.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            return await database.ManagementAuditEvents.AsNoTracking()
                .Where(audit => audit.Capability == DelegatedCredentialEvents.Capability)
                .ToListAsync();
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await Host.DisposeAsync();
            _factory.Dispose();
        }

        private static async Task SeedAsync(IServiceProvider services)
        {
            var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
            foreach (var name in new[] { DelegationScope, PrivateScope })
            {
                await scopes.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = name,
                    Resources = { TestDataSeeder.IntrospectionClientId },
                });
            }

            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            foreach (var (clientId, secret) in new[]
            {
                (DelegatorClientId, DelegatorClientSecret),
                (OtherCallerClientId, OtherCallerClientSecret),
            })
            {
                await applications.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = clientId,
                    ClientSecret = secret,
                    ClientType = ClientTypes.Confidential,
                    DisplayName = "Delegating test application",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.TokenExchange,
                        Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                        Permissions.Prefixes.Scope + DelegationScope,
                        Permissions.Prefixes.Scope + PrivateScope,
                    },
                });
            }

            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = DelegateClientId,
                ClientType = ClientTypes.Public,
                DisplayName = "Test device",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                },
            });
        }
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        private readonly List<(string Email, string Subject, string Body)> _messages = [];

        public IReadOnlyList<(string Email, string Subject, string Body)> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            lock (_messages)
            {
                _messages.Add((email, subject, htmlMessage));
            }

            return Task.CompletedTask;
        }
    }
}
