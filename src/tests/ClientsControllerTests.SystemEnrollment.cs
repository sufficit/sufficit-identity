using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Management.SystemUsers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task Update_existing_system_enrollment_client_preserves_grant_and_adds_scope()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        const string id = "example-system-worker";
        using (var scope = factory.Services.CreateScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = id, ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Explicit,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.RefreshToken,
                    "gt:" + SystemUserEnrollmentProtocol.GrantType,
                    "scp:example.read"
                }
            });
        }
        var before = await client.GetFromJsonAsync<ManagementClientDetail>("/api/clients/" + id);
        using var response = await client.PutAsJsonAsync("/api/clients/" + id, new UpdateClientRequest
        {
            DisplayName = "Example worker",
            ConsentType = ConsentTypes.Explicit,
            ExpectedVersion = before!.Version,
            GrantTypes = [SystemUserEnrollmentProtocol.GrantType, "refresh_token"],
            Scopes = ["example.read", "example.write"]
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var after = await client.GetFromJsonAsync<ManagementClientDetail>("/api/clients/" + id);
        Assert.Contains("gt:" + SystemUserEnrollmentProtocol.GrantType, after!.Permissions);
        Assert.Contains(Permissions.Endpoints.Token, after.Permissions);
        Assert.Contains(Permissions.GrantTypes.RefreshToken, after.Permissions);
        Assert.Contains("scp:example.read", after.Permissions);
        Assert.Contains("scp:example.write", after.Permissions);
    }

    [Theory]
    [InlineData("")]
    [InlineData("gt:")]
    public void System_enrollment_is_known_but_still_subject_to_source_allowlist(string prefix)
    {
        var validator = new ClientDefinitionValidator(new ReservedScopePolicy([]));
        var request = new ClientDefinitionRequest(
            ClientDefinitionSource.Management, "example-worker", "public",
            [prefix + SystemUserEnrollmentProtocol.GrantType], [], [],
            RequirePkce: false, HasClientSecret: false);
        Assert.True(validator.Validate(request).IsValid);
        var restricted = request with { AllowedGrantTypes = new HashSet<string> { "authorization_code" } };
        Assert.Contains(validator.Validate(restricted).Issues, i => i.Code == "grant_type_not_allowed");
    }
}
