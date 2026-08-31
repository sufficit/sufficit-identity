using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Server.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementApplicationAuthorizationTests
{
    [Fact]
    public async Task Service_principal_gets_what_its_role_maps_to()
    {
        var evaluator = CreateEvaluator(
            roleCapabilities: new() { [VaultRole] = [ManagementCapabilities.VaultSecretsManage] },
            clientRoles: [VaultRole]);

        var concedida = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));
        var fora = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.UsersDelete,
            new ManagementResource(ManagementResourceTypes.User));

        Assert.True(concedida.IsAllowed);
        Assert.Equal(ManagementAuthorizationOutcome.Denied, fora.Outcome);
    }

    [Fact]
    public async Task Service_principal_passes_mfa_for_what_its_role_grants()
    {
        // O ponto: com RequireMfa ligado e sem `amr`, a capacidade do papel
        // passa. Exigir segundo fator de quem se autenticou com segredo de
        // cliente não é uma trava, é negação permanente.
        var evaluator = CreateEvaluator(
            requireMfa: true,
            adminRoles: [],
            roleCapabilities: new() { [VaultRole] = [ManagementCapabilities.VaultSecretsManage] },
            clientRoles: [VaultRole]);

        var decisao = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.True(decisao.IsAllowed);
    }

    [Fact]
    public async Task Another_client_gets_nothing_from_someone_elses_roles()
    {
        var evaluator = CreateEvaluator(
            requireMfa: true,
            roleCapabilities: new() { [VaultRole] = [ManagementCapabilities.VaultSecretsManage] },
            clientRoles: [VaultRole]);

        var outro = await evaluator.EvaluateAsync(
            MachinePrincipal("dcr_algum_cliente_anonimo"),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, outro.Outcome);
    }

    [Fact]
    public async Task A_human_holding_the_same_capability_still_needs_mfa()
    {
        // A isenção não pode vazar para operador: ele recebeu a capacidade por
        // claim `permission`, não por ser máquina.
        var evaluator = CreateEvaluator(
            requireMfa: true,
            adminRoles: [],
            roleCapabilities: new() { [VaultRole] = [ManagementCapabilities.VaultSecretsManage] },
            clientRoles: [VaultRole]);

        var humano = await evaluator.EvaluateAsync(
            PrincipalWithClaims(
                new Claim("permission", ManagementCapabilities.VaultSecretsManage)),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            humano.Outcome);
    }

    [Fact]
    public async Task Client_without_declared_roles_changes_nothing()
    {
        // Estado padrão de todo cliente que existe hoje: sem a propriedade, o
        // comportamento tem de ser exatamente o de antes desta mudança.
        var evaluator = CreateEvaluator(
            requireMfa: true,
            adminRoles: [],
            roleCapabilities: new() { [VaultRole] = [ManagementCapabilities.VaultSecretsManage] },
            clientRoles: []);

        var maquina = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, maquina.Outcome);
    }

    private static ClaimsPrincipal MachinePrincipal(string clientId) =>
        new(new ClaimsIdentity(
            [
                // sub == client_id é o que marca a máquina: o handler de
                // client_credentials põe o próprio cliente como subject porque
                // não há mais ninguém para pôr.
                new Claim("sub", clientId),
                new Claim("client_id", clientId)
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));

    private sealed class FakeRoleSource(string clientId, string[] roles)
        : IServicePrincipalRoleSource
    {
        public ValueTask<IReadOnlyCollection<string>> RolesAsync(
            string requested, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IReadOnlyCollection<string>>(
                string.Equals(requested, clientId, StringComparison.Ordinal) ? roles : []);
    }
}
