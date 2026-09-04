using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.ServiceAccounts;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Criação de conta de sistema pela tela de gestão.
/// </summary>
/// <remarks>
/// A tela existia apenas para EDITAR papéis de contas já criadas por outro
/// caminho. Criar uma conta é conceder privilégio — o papel vira capacidade de
/// gestão — então o que estes testes fixam não é só "criou", é a FORMA da conta
/// criada: confidencial, só <c>client_credentials</c>, sem redirect, e com os
/// papéis validados contra o que a implantação reconhece.
/// </remarks>
public sealed class ServiceAccountCreationTests
{
    private static async Task<ManagementTestFactory> CreateFactoryAsync()
    {
        var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        return factory;
    }

    [Fact]
    public async Task Creates_a_confidential_client_credentials_account()
    {
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = $"svc-{Guid.NewGuid():N}";

        var created = await accounts.CreateAsync(
            new CreateServiceAccountCommand(clientId, "Conta de teste"),
            Context());

        Assert.Equal(clientId, created.Account.ClientId);
        Assert.True(created.Account.CanRequestTokens);
        // O segredo volta uma única vez e precisa ser utilizável.
        Assert.False(string.IsNullOrWhiteSpace(created.ClientSecret));
        Assert.True(created.ClientSecret.Length >= 32);

        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);

        var permissions = await applications.GetPermissionsAsync(application!);
        Assert.Contains(
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Endpoints.Token, permissions);
        Assert.Contains(
            OpenIddictConstants.Permissions.Prefixes.Scope + "identity.management",
            permissions);

        // Sem fluxo interativo: uma conta de máquina que aceitasse
        // authorization_code seria uma porta de entrada com usuário nenhum
        // atrás dela.
        Assert.DoesNotContain(
            OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
            permissions);
        Assert.Empty(await applications.GetRedirectUrisAsync(application!));
        Assert.Equal(
            OpenIddictConstants.ClientTypes.Confidential,
            await applications.GetClientTypeAsync(application!));
    }

    [Fact]
    public async Task Returned_secret_authenticates_the_account()
    {
        // O segredo volta uma única vez; se não servir para autenticar, a conta
        // nasce inutilizável e o operador só descobre no primeiro token.
        // OpenIddict não expõe leitura do segredo (guarda só o hash), então a
        // verificação correta é validá-lo — que de quebra prova o hashing.
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = $"svc-{Guid.NewGuid():N}";

        var created = await accounts.CreateAsync(
            new CreateServiceAccountCommand(clientId),
            Context());

        var application = await applications.FindByClientIdAsync(clientId);
        Assert.True(await applications.ValidateClientSecretAsync(
            application!,
            created.ClientSecret));
        Assert.False(await applications.ValidateClientSecretAsync(
            application!,
            created.ClientSecret + "-errado"));
    }

    [Fact]
    public async Task Rejects_a_duplicate_client_id()
    {
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();
        var clientId = $"svc-{Guid.NewGuid():N}";

        await accounts.CreateAsync(new CreateServiceAccountCommand(clientId), Context());

        var failure = await Assert.ThrowsAsync<ManagementValidationException>(
            () => accounts.CreateAsync(
                new CreateServiceAccountCommand(clientId),
                Context()));
        Assert.Equal("client_already_exists", failure.ReasonCode);
    }

    [Fact]
    public async Task Rejects_an_unknown_role_instead_of_creating_a_powerless_account()
    {
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = $"svc-{Guid.NewGuid():N}";

        var failure = await Assert.ThrowsAsync<ManagementValidationException>(
            () => accounts.CreateAsync(
                new CreateServiceAccountCommand(
                    clientId,
                    Roles: ["papel-que-nao-existe"]),
                Context()));

        Assert.Equal("unknown_role", failure.ReasonCode);
        // E não pode ter deixado a conta para trás: uma conta criada sem o
        // papel pedido é pior que erro nenhum, porque parece pronta.
        Assert.Null(await applications.FindByClientIdAsync(clientId));
    }

    [Fact]
    public async Task Rejects_an_empty_client_id()
    {
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();

        var failure = await Assert.ThrowsAsync<ManagementValidationException>(
            () => accounts.CreateAsync(
                new CreateServiceAccountCommand("   "),
                Context()));
        Assert.Equal("client_id_required", failure.ReasonCode);
    }

    [Fact]
    public async Task Created_account_appears_in_the_workspace()
    {
        using var factory = await CreateFactoryAsync();
        using var scope = factory.Services.CreateScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IServiceAccountManagementService>();
        var clientId = $"svc-{Guid.NewGuid():N}";

        await accounts.CreateAsync(
            new CreateServiceAccountCommand(clientId, "Visível na lista"),
            Context());

        var workspace = await accounts.GetWorkspaceAsync(Context());

        Assert.Contains(workspace.Accounts, a => a.ClientId == clientId);
    }

    private static ManagementRequestContext Context() =>
        new(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, "operator-administrator"),
                        new Claim(ClaimTypes.Role, "administrator"),
                    ],
                    "test",
                    ClaimTypes.Name,
                    ClaimTypes.Role)),
            $"test-{Guid.NewGuid():N}");
}
