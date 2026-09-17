using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Tokens;

namespace Sufficit.Identity.STS;

public static partial class ServiceCollectionExtensions
{
    /// <summary>Maintenance-only composition: no HTTP, provisioning, migrations or hosted workers.</summary>
    public static IServiceCollection AddSufficitIdentityTokenPruning(
        this IServiceCollection services, SufficitIdentityOptions options,
        string connectionString, bool isDevelopment)
    {
        DatabaseTransportPolicy.Validate(connectionString, options.Database.TransportMode, isDevelopment);
        var configured = ApplyDatabaseConnectionPolicy(connectionString, options.Database.ConnectionPool);
        services.AddMemoryCache();
        services.AddDbContext<AppDbContext>(db =>
        {
            db.UseMySql(configured, MariaDbServerVersion.AutoDetect(configured));
            db.UseOpenIddict();
        });
        services.AddOpenIddict().AddCore(core =>
        {
            core.UseEntityFrameworkCore().UseDbContext<AppDbContext>();
            core.ReplaceTokenStore<OpenIddictEntityFrameworkCoreToken, SufficitOpenIddictTokenStore>();
        });
        // MariaDB does not support OpenIddict's bulk DELETE with LIMIT in a subquery.
        services.Configure<OpenIddictEntityFrameworkCoreOptions>(o => o.DisableBulkOperations = true);
        services.AddSingleton<OpenIddictPruningService>();
        return services;
    }
}
