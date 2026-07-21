using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Sufficit.Exchange;
using Sufficit.Exchange.EMail;
using Sufficit.Identity;
using Sufficit.Identity.Core;
using Sufficit.Notification;

namespace Sufficit.Identity.Server.Email;

/// <summary>
/// <see cref="IEmailSender"/> that publishes <see cref="EMailMessage"/> items to
/// the Sufficit RabbitMQ broker (queue <c>Q-EMAIL</c>) via
/// <see cref="IExchangeBrokerService"/>.
///
/// Ported from the legacy Skoruba STS
/// (Skoruba.Duende.IdentityServer.Shared.Configuration.Services.RabbitMQEmailQueue)
/// to keep behavioral parity with the production email pipeline:
///  - Detects password-reset vs. email-confirmation by subject/body keywords
///  - Sets the ModelId to one of two well-known GUIDs that the downstream
///    consumer of the Q-EMAIL queue uses to catalog/triage the message
///    (these GUIDs are part of the contract and MUST stay identical):
///      EmailConfirmationINotificationEvent.UniqueID
///      PasswordResetINotificationEvent.UniqueID
///  - Optionally renders the body using the "Padrao" template via
///    <see cref="NotificationPool"/> when registered (DI optional); otherwise
///    the html message is published as-is.
///  - When <see cref="EmailOptions.TestEmailAddress"/> is configured, ALL
///    outgoing emails are redirected to that test address (dev/staging safety).
/// </summary>
public sealed class RabbitMQEmailQueue : IEmailSender
{
    private readonly IExchangeBrokerService _exchange;
    private readonly ILogger<RabbitMQEmailQueue> _logger;
    private readonly NotificationPool? _pool;
    private readonly EmailOptions _emailOptions;

    public RabbitMQEmailQueue(
        IExchangeBrokerService exchange,
        ILogger<RabbitMQEmailQueue> logger,
        EmailOptions emailOptions,
        NotificationPool? pool = null)
    {
        _exchange = exchange;
        _logger = logger;
        _emailOptions = emailOptions;
        _pool = pool;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        htmlMessage ??= string.Empty;

        // Test-mode override: redirect to TestEmailAddress when configured.
        var recipient = EmailRecipientResolver.Resolve(email, _emailOptions);
        if (!string.Equals(recipient, email, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("TEST MODE: redirecting email from {Original} to {Test}", email, recipient);
        }

        var emailConfirmationModelId = Guid.Parse(EmailConfirmationINotificationEvent.UniqueID);
        var passwordResetModelId = Guid.Parse(PasswordResetINotificationEvent.UniqueID);

        // Heurística mantida idêntica ao legado. Mudar quebra o contrato com
        // o consumidor da fila Q-EMAIL (que tria por ModelId).
        var isPasswordReset =
            (!string.IsNullOrWhiteSpace(htmlMessage)
             && (
                 htmlMessage.Contains("ResetPassword", StringComparison.OrdinalIgnoreCase)
                 || htmlMessage.Contains("/Account/ResetPassword", StringComparison.OrdinalIgnoreCase)
                 || htmlMessage.Contains("/account/resetpassword", StringComparison.OrdinalIgnoreCase)
             ))
            || (!string.IsNullOrWhiteSpace(subject)
                && subject.Contains("Reset", StringComparison.OrdinalIgnoreCase));

        var modelId = isPasswordReset ? passwordResetModelId : emailConfirmationModelId;
        var messageId = Guid.NewGuid();

        var bodyHtml = htmlMessage;
        var actionLink = TryExtractFirstHref(htmlMessage);
        if (_pool is not null && !string.IsNullOrWhiteSpace(actionLink))
        {
            try
            {
                var parameters = new TemplateParameters
                {
                    Title = $"#SUFFICIT - {subject}",
                    Text = isPasswordReset
                        ? "Clique em continuar para redefinir sua senha. Se você não solicitou isso, ignore este e-mail."
                        : "Clique em continuar para confirmar seu e-mail. Se você não solicitou isso, ignore este e-mail.",
                    Preview = isPasswordReset
                        ? "Clique em continuar para redefinir sua senha."
                        : "Clique em continuar para confirmar seu e-mail.",
                    ActionText = isPasswordReset ? "redefinir minha senha" : "confirmar meu e-mail",
                    ActionLink = actionLink,
                    Note = string.Empty
                };

                bodyHtml = await _pool.EMailBodyGenerate(parameters, "Padrao", default);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "failed to generate standard email HTML template; falling back to original htmlMessage");
                bodyHtml = htmlMessage;
            }
        }

        _logger.LogInformation(
            "sending mail to {Email} with subject: {Subject} (ModelId: {ModelId}, MessageId: {MessageId}, Kind: {Kind})",
            recipient, subject, modelId, messageId,
            isPasswordReset ? "password-reset" : "email-confirmation");

        var message = new EMailMessage(messageId)
        {
            ModelId = modelId,
            Subject = subject,
            Body = System.Text.Encoding.UTF8.GetBytes(bodyHtml),
            Recipient = recipient
        };

        await _exchange.EnqueueAsync(message, default);

        _logger.LogInformation(
            "mail enqueued to exchange (ModelId: {ModelId}, MessageId: {MessageId}, Recipient: {Email})",
            modelId, messageId, recipient);
    }

    /// <summary>
    /// Extracts the value of the FIRST <c>href</c> attribute in the HTML.
    /// Matches legacy behavior (case-insensitive, single/double quotes).
    /// </summary>
    private static string? TryExtractFirstHref(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
            return null;

        var match = Regex.Match(
            html,
            @"href\s*=\s*[""'](?<href>[^""']+)[""']",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        if (!match.Success)
            return null;

        var href = match.Groups["href"]?.Value;
        return string.IsNullOrWhiteSpace(href) ? null : href;
    }
}
