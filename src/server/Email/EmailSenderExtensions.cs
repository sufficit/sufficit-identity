using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Exchange;
using Sufficit.Identity.Server.Email;

namespace Sufficit.Identity.Server;

public static class EmailSenderExtensions
{
    /// <summary>
    /// Registers <see cref="RabbitMQEmailQueue"/> as the <see cref="IEmailSender"/>
    /// for the Sufficit production email pipeline.
    ///
    /// Activates only when the <c>Sufficit:Exchange:RabbitMQ:HostName</c>
    /// configuration value is present. When absent, the caller should leave
    /// the default IEmailSender registered by the UI layer (SmtpEmailSender
    /// or LoggingEmailSender).
    ///
    /// <para>
    /// Schema (matches the legacy Skoruba STS):
    /// <code>
    /// "Sufficit": {
    ///   "Exchange": {
    ///     "RabbitMQ": {
    ///       "Persistent": true,
    ///       "HostName": "exchange.sufficit.com.br",
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
        IConfiguration configuration)
    {
        var hostName = configuration["Sufficit:Exchange:RabbitMQ:HostName"];
        if (string.IsNullOrWhiteSpace(hostName))
        {
            // Broker not configured — caller's default IEmailSender wins.
            return services;
        }

        // Register IExchangeBrokerService / RabbitMQ connection via the
        // extension shipped in the Sufficit.Communication package.
        services.AddSufficitExchange(configuration);

        // Replace any IEmailSender previously registered by the UI layer
        // (SmtpEmailSender / LoggingEmailSender) with the RabbitMQ queue.
        services.Replace(ServiceDescriptor.Transient<IEmailSender, RabbitMQEmailQueue>());

        return services;
    }
}
