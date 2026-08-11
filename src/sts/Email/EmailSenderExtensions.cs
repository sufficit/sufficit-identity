using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS;

public static class EmailSenderExtensions
{
    /// <summary>
    /// Registers <see cref="RabbitMQEmailQueue"/> as the <see cref="IEmailSender"/>
    /// for the Sufficit production email pipeline.
    ///
    /// Activates only when the <c>Sufficit:Exchange:RabbitMQ:HostName</c>
    /// configuration value is present. When absent, the caller should leave
    /// the default IEmailSender registered by the STS runtime (SmtpEmailSender
    /// or LoggingEmailSender).
    ///
    /// <para>
    /// Schema (matches the legacy Skoruba STS):
    /// <code>
    /// "Sufficit": {
    ///   "Exchange": {
    ///     "RabbitMQ": {
    ///       "Persistent": true,
    ///       "HostName": "smtp.example.com",
    ///       "UserName": "identity",
    ///       "Password": "&lt;secret&gt;",
    ///       "Heartbeat": null
    ///     }
    ///   }
    /// }
    /// </code>
    /// </para>
    /// </summary>
    public static IServiceCollection AddSufficitEmailSender(
        this IServiceCollection services,
        IConfiguration configuration,
        ISecretStore? secretStore = null)
    {
        var startupSecretStore = secretStore
            ?? new EnvironmentSecretStore();
        var hostName = configuration["Sufficit:Exchange:RabbitMQ:HostName"];
        if (string.IsNullOrWhiteSpace(hostName))
        {
            // Broker not configured — caller's default IEmailSender wins.
            return services;
        }

        var rabbitOptions = configuration
            .GetSection(RabbitMqEmailOptions.SectionName)
            .Get<RabbitMqEmailOptions>() ?? new RabbitMqEmailOptions();
        if (rabbitOptions.RequireTls && !rabbitOptions.UseTls)
        {
            throw new InvalidOperationException(
                "RabbitMQ RequireTls=true requires UseTls=true.");
        }
        if (!rabbitOptions.UseTls
            && !string.Equals(
                Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
                "Development",
                StringComparison.Ordinal))
        {
            Console.Error.WriteLine(
                "[WARNING] RabbitMQ email transport is using plaintext AMQP compatibility mode. Enable UseTls, verify broker certificates, then set RequireTls=true.");
        }

        var rabbitPassword = startupSecretStore.GetSecretAsync(
                "exchange/rabbitmq/password")
            .GetAwaiter()
            .GetResult();
        services.Configure<RabbitMqEmailOptions>(
            configuration.GetSection(RabbitMqEmailOptions.SectionName));
        services.PostConfigure<RabbitMqEmailOptions>(options =>
            options.Password = rabbitPassword ?? string.Empty);
        services.TryAddSingleton<IEmailMessagePublisher, RabbitMqEmailPublisher>();

        // Replace the default IEmailSender registered by the STS runtime
        // (SmtpEmailSender / LoggingEmailSender) with the RabbitMQ queue.
        services.Replace(ServiceDescriptor.Transient<IEmailSender, RabbitMQEmailQueue>());

        return services;
    }
}
