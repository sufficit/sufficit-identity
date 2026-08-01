using System.Net;
using System.Net.Mail;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// SMTP-based <see cref="IEmailSender"/> that sends email via a configurable
/// SMTP server. Used in production when SMTP credentials are available.
/// Configure via "Sufficit:Identity:Smtp" section:
///   Host, Port, Login, Password, From (email), FromName.
/// </summary>
public sealed class SmtpEmailSender : IEmailSender, IDisposable
{
    private readonly SmtpConfiguration _config;
    private readonly EmailOptions _emailOptions;
    private readonly ILogger<SmtpEmailSender> _logger;
    private readonly SmtpClient? _client;

    public SmtpEmailSender(IConfiguration configuration, EmailOptions emailOptions, ILogger<SmtpEmailSender> logger)
    {
        _logger = logger;
        _emailOptions = emailOptions;
        _config = configuration
            .GetSection("Sufficit:Identity:Smtp")
            .Get<SmtpConfiguration>() ?? new SmtpConfiguration();

        if (!string.IsNullOrWhiteSpace(_config.Host))
        {
            _client = new SmtpClient(_config.Host, _config.Port > 0 ? _config.Port : 587)
            {
                EnableSsl = _config.EnableSsl,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = string.IsNullOrWhiteSpace(_config.Login),
            };
            if (!string.IsNullOrWhiteSpace(_config.Login))
            {
                _client.Credentials = new NetworkCredential(_config.Login, _config.Password);
            }
        }
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        if (_client is null)
        {
            // Never log the body here either — it may carry a reset/confirmation
            // token. This should not happen in practice (SmtpEmailSender is only
            // registered when Sufficit:Identity:Smtp:Host is set), but guard it the
            // same way as LoggingEmailSender in case Host was cleared at runtime.
            _logger.LogError("SMTP client not initialized. Email to {Email} subject '{Subject}' was NOT sent.",
                email, subject);
            return;
        }

        var recipient = EmailRecipientResolver.Resolve(email, _emailOptions);
        if (!string.Equals(recipient, email, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("TEST MODE: redirecting email from {Original} to {Test}", email, recipient);
        }

        var from = new MailAddress(_config.From ?? "no-reply@sufficit.com.br", _config.FromName ?? "Sufficit Identity");
        var to = new MailAddress(recipient);
        using var msg = new MailMessage(from, to)
        {
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true,
        };

        try
        {
            await _client.SendMailAsync(msg);
            _logger.LogInformation("Email sent to {Email} subject '{Subject}'", recipient, subject);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Email} subject '{Subject}'", recipient, subject);
            throw;
        }
    }

    public void Dispose() => _client?.Dispose();
}

/// <summary>
/// Fallback <see cref="IEmailSender"/> used when no real transport (SMTP/RabbitMQ)
/// is configured.
///
/// SECURITY: this sender must NEVER log the email body. The body of a password
/// reset / email confirmation / 2FA recovery message IS a bearer credential — a
/// reset link contains a token that grants account access to whoever reads it, so
/// writing it to application logs (which are typically far less protected than an
/// inbox, often shipped to log aggregators, retained long-term, and readable by a
/// wider audience) hands out account-takeover capability to anyone with log access.
///
/// In Development, this sender logs a safe preview (recipient + subject only, no
/// body/link/token) so a developer knows an email "would have" been sent. Outside
/// Development, reaching this sender at all means SMTP/RabbitMQ were not
/// configured — that's a production misconfiguration silently dropping
/// security-critical email, so it fails loudly (logs an error without the body,
/// then throws) instead of pretending delivery succeeded.
/// </summary>
public sealed class LoggingEmailSender : IEmailSender
{
    private readonly EmailOptions _emailOptions;
    private readonly ILogger<LoggingEmailSender> _logger;
    private readonly IHostEnvironment _environment;

    public LoggingEmailSender(EmailOptions emailOptions, ILogger<LoggingEmailSender> logger, IHostEnvironment environment)
    {
        _emailOptions = emailOptions;
        _logger = logger;
        _environment = environment;
    }

    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        var recipient = EmailRecipientResolver.Resolve(email, _emailOptions);
        if (!string.Equals(recipient, email, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("TEST MODE: redirecting email from {Original} to {Test}", email, recipient);
        }

        if (_environment.IsDevelopment())
        {
            // Dev-only safe preview: recipient + subject, NEVER the body (no
            // link/token) — a developer who needs the actual reset/confirm link
            // should configure Sufficit:Identity:Smtp or use the mailbox directly.
            _logger.LogInformation(
                "[EMAIL preview — no transport configured, body omitted] To: {Email}  Subject: {Subject}",
                recipient, subject);
        }
        else
        {
            _logger.LogError(
                "No email transport (SMTP/RabbitMQ) is configured outside Development. " +
                "Email to {Email} subject '{Subject}' was NOT delivered.",
                recipient, subject);

            throw new InvalidOperationException(
                "LoggingEmailSender cannot be used outside Development: configure " +
                "Sufficit:Identity:Smtp (or the RabbitMQ email queue) so account-security " +
                "emails (password reset, confirmation, 2FA recovery) are actually delivered.");
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// SMTP server configuration bound from "Sufficit:Identity:Smtp".
/// </summary>
public sealed class SmtpConfiguration
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? Login { get; set; }
    public string? Password { get; set; }
    public bool EnableSsl { get; set; } = true;
    public string? From { get; set; }
    public string? FromName { get; set; }
}
