using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.ServiceAccounts;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A tela de contas de sistema edita a MESMA propriedade que o
/// <c>ServicePrincipalEntitlementResolver</c> consulta, então o que estes
/// testes protegem é a coerência entre o que o operador vê e o que o
/// avaliador vai conceder.
/// </summary>
public sealed class ServiceAccountManagementTests
{
    [Fact]
    public void Known_roles_come_from_both_maps_and_resolve_like_the_evaluator()
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                FullAdministratorRoles = ["administrator"],
                RoleCapabilities = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["mobilecloudadministrator"] =
                    [
                        ManagementCapabilities.VaultSecretsManage,
                        "identity.capability.que.nao.existe",
                    ]
                }
            }
        });

        var workspace = typeof(ServiceAccountManagementService)
            .GetMethod("KnownRoles",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [options.Value.Authorization])
            as IReadOnlyList<ServiceAccountRoleOption>;

        Assert.NotNull(workspace);
        var admin = Assert.Single(workspace!, option => option.IsFullAdministrator);
        Assert.Equal("administrator", admin.Role);
        Assert.Equal(ManagementCapabilities.All.Count, admin.Capabilities.Count);

        var vault = Assert.Single(workspace!, option => !option.IsFullAdministrator);
        // O nome inventado cai fora — a tela mostra exatamente o que o
        // avaliador concederia, e o avaliador ignora capability desconhecida.
        Assert.Equal([ManagementCapabilities.VaultSecretsManage], vault.Capabilities);
    }
}
