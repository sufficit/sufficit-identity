namespace Sufficit.Identity.Core;

/// <summary>
/// Email pipeline options shared by all <c>IEmailSender</c> implementations
/// (SmtpEmailSender, LoggingEmailSender, RabbitMQEmailQueue).
/// Bound from the <c>Sufficit:Identity:Email</c> configuration section.
/// </summary>
public sealed class EmailOptions
{
    /// <summary>
    /// When non-empty, ALL outgoing emails (regardless of original recipient)
    /// are redirected to this address. Useful for development / staging so
    /// that automated tests and manual trials never deliver to real users.
    ///
    /// Leave empty in production.
    /// </summary>
    public string? TestEmailAddress { get; set; }
}

/// <summary>
/// Helpers for resolving the actual recipient of an email, honoring the
/// <see cref="EmailOptions.TestEmailAddress"/> override.
/// </summary>
public static class EmailRecipientResolver
{
    /// <summary>
    /// Returns the recipient that should actually receive the message:
    /// <c>TestEmailAddress</c> when configured (testing), otherwise the
    /// original recipient.
    /// </summary>
    public static string Resolve(string originalRecipient, EmailOptions? options)
    {
        if (options is null || string.IsNullOrWhiteSpace(options.TestEmailAddress))
        {
            return originalRecipient;
        }
        return options.TestEmailAddress!;
    }
}
