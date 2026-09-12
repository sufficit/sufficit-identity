using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Delivers the message that proves control of an email address before an
/// external identity is allowed to create an account.
/// </summary>
/// <remarks>
/// Kept separate from <c>IAccountOnboardingService</c> on purpose. That contract
/// is about local registration and recovery; widening it with an external-link
/// concern would make every implementer of the boundary carry a method most of
/// them do not need.
/// </remarks>
public sealed class ExternalIdentityVerificationMessenger(
    IEmailSender emailSender,
    IHttpContextAccessor httpContextAccessor,
    IPublicOriginResolver publicOrigin,
    SufficitIdentityOptions options,
    ILogger<ExternalIdentityVerificationMessenger> logger)
{
    public const string ConfirmationPath = "/account/externallink/confirm";

    /// <summary>
    /// Sends the redemption link. Returns whether delivery was accepted; the
    /// caller must not change its answer based on that, because telling the
    /// browser whether a message went out is itself an account oracle.
    /// </summary>
    public async Task<bool> SendAsync(
        string email,
        string ticket,
        string providerDisplayName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var request = httpContextAccessor.HttpContext?.Request
                ?? throw new InvalidOperationException(
                    "An HTTP request is required to build the external link "
                    + "confirmation URL.");
            var pathWithQuery = QueryHelpers.AddQueryString(
                ConfirmationPath,
                "ticket",
                ticket);
            var callbackUrl = publicOrigin.BuildAbsolute(request, pathWithQuery);
            var product = options.Branding.ProductName;
            var body =
                $"Confirme que este endereço é seu para concluir o acesso por "
                + $"{HtmlEncoder.Default.Encode(providerDisplayName)}: "
                + $"<a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clique aqui</a>. "
                + "Se você não iniciou este acesso, ignore esta mensagem — "
                + "nenhuma conta foi criada.";
            await emailSender.SendEmailAsync(
                email,
                $"Confirme seu e-mail — {product}",
                body);
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "External link verification message delivery failed for "
                + "provider {Provider}.",
                providerDisplayName);
            return false;
        }
    }
}
