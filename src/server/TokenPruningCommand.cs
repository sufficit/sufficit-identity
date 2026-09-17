using System.Runtime.InteropServices;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Tokens;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Server;

internal static class TokenPruningCommand
{
    internal static async Task<int> RunAsync(bool checkOnly)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            EnvironmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
                ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"
        });
        builder.Configuration.AddMachineSpecificJsonFile();
        builder.Configuration.AddEnvironmentVariables();
        var options = builder.Configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new();
        var pruning = options.TokenPruning;
        using var logs = LoggerFactory.Create(b => b.AddSimpleConsole(o => o.SingleLine = true));
        var logger = logs.CreateLogger("Sufficit.Identity.TokenPruning");
        try
        {
            if (string.IsNullOrWhiteSpace(pruning.StatePath) || !Path.IsPathFullyQualified(pruning.StatePath)
                || pruning.AlertAfterHours <= 0 || pruning.TimeoutMinutes <= 0)
                throw new InvalidOperationException("Invalid pruning configuration.");
            if (checkOnly)
            {
                var state = await TokenPruningState.ReadFreshAsync(pruning.StatePath,
                    DateTimeOffset.UtcNow, TimeSpan.FromHours(pruning.AlertAfterHours));
                logger.LogInformation("TokenPruningHealthy LastSuccessUtc={LastSuccessUtc}", state.LastSuccessUtc);
                return 0;
            }
            using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(pruning.TimeoutMinutes));
            using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM,
                context => { context.Cancel = true; stop.Cancel(); });
            using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT,
                context => { context.Cancel = true; stop.Cancel(); });
            var connection = await new EnvironmentSecretStore().GetSecretAsync("database/connection-string", stop.Token)
                ?? throw new InvalidOperationException("Database secret is not configured.");
            builder.Services.AddSufficitIdentityTokenPruning(options, connection, builder.Environment.IsDevelopment());
            // Building the container never starts the generic host or any hosted service.
            using var host = builder.Build();
            var runner = host.Services.GetRequiredService<OpenIddictPruningService>();
            var result = await TokenPruningState.RunAsync(pruning.StatePath,
                ct => runner.PruneAsync(pruning.RetentionDays, ct), stop.Token);
            logger.LogInformation("TokenPruningSucceeded LastSuccessUtc={LastSuccessUtc} Tokens={Tokens} Authorizations={Authorizations}",
                result.LastSuccessUtc, result.Tokens, result.Authorizations);
            return 0;
        }
        catch (Exception error)
        {
            // Never print connection strings or exception payloads containing deployment secrets.
            logger.LogWarning("{Event} FailureType={FailureType} MaximumAgeHours={MaximumAgeHours}",
                checkOnly ? "TokenPruningOverdue" : "TokenPruningFailed", error.GetType().Name, pruning.AlertAfterHours);
            return 1;
        }
    }
}
