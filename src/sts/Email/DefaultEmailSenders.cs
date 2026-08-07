using System.Net;
using System.Net.Mail;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core;

namespace Sufficit.Identity.STS.Email;

/// <summary>SMTP transport for runtime-owned account security messages.</summary>
public sealed class SmtpEmailSender : IEmailSender, IDisposable
{
    private readonly SmtpConfiguration _configuration;
    private readonly EmailOptions _emailOptions;
    private readonly ILogger<SmtpEmailSender> _logger;
    private readonly SmtpClient? _client;

    public SmtpEmailSender(
        IConfiguration configuration,
        EmailOptions emailOptions,
        ILogger<SmtpEmailSender> logger)
    {
        _logger = logger;
        _emailOptions = emailOptions;
        _configuration = configuration
            .GetSection("Sufficit:Identity:Smtp")
            .Get<SmtpConfiguration>() ?? new SmtpConfiguration();
        if (string.IsNullOrWhiteSpace(_configuration.Host))
            return;

        if (_configuration.RequireTls && !_configuration.EnableSsl)
        {
            throw new InvalidOperationException(
                "SMTP RequireTls=true requires EnableSsl=true.");
        }
        if (!_configuration.EnableSsl
            && !string.Equals(
                Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
                "Development",
                StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "SMTP is using plaintext compatibility mode. Enable SSL and then set RequireTls=true.");
        }

        _client = new SmtpClient(
            _configuration.Host,
            _configuration.Port > 0 ? _configuration.Port : 587)
        {
            EnableSsl = _configuration.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = string.IsNullOrWhiteSpace(
                _configuration.Login),
        };
        if (!string.IsNullOrWhiteSpace(_configuration.Login))
        {
            _client.Credentials = new NetworkCredential(
                _configuration.Login,
                _configuration.Password);
        }
    }

    public async Task SendEmailAsync(
        string email,
        string subject,
        string htmlMessage)
    {
        if (_client is null)
        {
            _logger.LogError(
                "SMTP client is not initialized. Message to {Email} with "
                + "subject {Subject} was not sent.",
                email,
                subject);
            return;
        }

        var recipient = EmailRecipientResolver.Resolve(email, _emailOptions);
        if (!string.Equals(
                recipient,
                email,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Test mode redirected email from {Original} to {Test}.",
                email,
                recipient);
        }

        var from = new MailAddress(
            _configuration.From ?? "no-reply@example.com",
            _configuration.FromName ?? "Sufficit Identity");
        var to = new MailAddress(recipient);
        using var message = new MailMessage(from, to)
        {
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true,
        };
        try
        {
            await _client.SendMailAsync(message);
            _logger.LogInformation(
                "Email sent to {Email} with subject {Subject}.",
                recipient,
                subject);
        }
        catch (Exception exception)
        {
            _logger.LogError(
                exception,
                "Email delivery to {Email} with subject {Subject} failed.",
                recipient,
                subject);
            throw;
        }
    }

    public void Dispose() => _client?.Dispose();
}

/// <summary>
/// Development-only fallback. Security-message bodies are never logged because
/// they contain bearer credentials such as reset and confirmation tokens.
/// </summary>
public sealed class LoggingEmailSender(
    EmailOptions emailOptions,
    ILogger<LoggingEmailSender> logger,
    IHostEnvironment environment) : IEmailSender
{
    public Task SendEmailAsync(
        string email,
        string subject,
        string htmlMessage)
    {
        var recipient = EmailRecipientResolver.Resolve(email, emailOptions);
        if (!string.Equals(
                recipient,
                email,
                StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Test mode redirected email from {Original} to {Test}.",
                email,
                recipient);
        }

        if (environment.IsDevelopment())
        {
            logger.LogInformation(
                "Email preview without body or transport: {Email}, {Subject}.",
                recipient,
                subject);
            return Task.CompletedTask;
        }

        logger.LogError(
            "No email transport is configured. Message to {Email} with subject "
            + "{Subject} was not delivered.",
            recipient,
            subject);
        throw new InvalidOperationException(
            "Configure Sufficit:Identity:Smtp or the RabbitMQ email queue "
            + "before sending account-security messages outside Development.");
    }
}

public sealed class SmtpConfiguration
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? Login { get; set; }
    public string? Password { get; set; }
    public bool EnableSsl { get; set; } = true;
    public bool RequireTls { get; set; } = false;
    public string? From { get; set; }
    public string? FromName { get; set; }
}
