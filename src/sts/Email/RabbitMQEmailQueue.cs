using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core;

namespace Sufficit.Identity.STS.Email;

/// <summary>
/// <see cref="IEmailSender"/> that publishes <see cref="EmailQueueMessage"/> items to
/// the Sufficit RabbitMQ broker (queue <c>Q-EMAIL</c>).
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
///  - When <see cref="EmailOptions.TestEmailAddress"/> is configured, ALL
///    outgoing emails are redirected to that test address (dev/staging safety).
/// </summary>
internal sealed class RabbitMQEmailQueue : IEmailSender
{
    internal static readonly Guid EmailConfirmationModelId =
        Guid.Parse("68951610-03b6-4b6c-9a25-c24b4e76f79f");
    internal static readonly Guid PasswordResetModelId =
        Guid.Parse("90d294f0-5102-4bec-b988-14e1a385ce61");

    private readonly IEmailMessagePublisher _publisher;
    private readonly ILogger<RabbitMQEmailQueue> _logger;
    private readonly EmailOptions _emailOptions;

    public RabbitMQEmailQueue(
        IEmailMessagePublisher publisher,
        ILogger<RabbitMQEmailQueue> logger,
        EmailOptions emailOptions)
    {
        _publisher = publisher;
        _logger = logger;
        _emailOptions = emailOptions;
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

        var modelId = isPasswordReset ? PasswordResetModelId : EmailConfirmationModelId;
        var messageId = Guid.NewGuid();

        _logger.LogInformation(
            "sending mail to {Email} with subject: {Subject} (ModelId: {ModelId}, MessageId: {MessageId}, Kind: {Kind})",
            recipient, subject, modelId, messageId,
            isPasswordReset ? "password-reset" : "email-confirmation");

        var message = new EmailQueueMessage
        {
            Id = messageId,
            ModelId = modelId,
            Subject = subject,
            Body = System.Text.Encoding.UTF8.GetBytes(htmlMessage),
            Recipient = recipient
        };

        await _publisher.PublishAsync(message, CancellationToken.None);

        _logger.LogInformation(
            "mail enqueued to exchange (ModelId: {ModelId}, MessageId: {MessageId}, Recipient: {Email})",
            modelId, messageId, recipient);
    }

}
