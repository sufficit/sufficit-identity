using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddictServerAspNetCoreHandlers =
    OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlers;

namespace Sufficit.Identity.STS.ErrorPages;

/// <summary>
/// Renders a browser-friendly, localized error page when an interactive
/// <c>/connect/authorize</c> request fails in a way that CANNOT be returned to
/// the relying party (no validated <c>redirect_uri</c> is recoverable).
/// </summary>
/// <remarks>
/// Why this exists (incident 2026-09-09, ID2013): OpenIddict 7.6 PAR
/// <c>request_uri</c> values are single-use (RFC 9126 §6.1). When a user
/// re-presents an already-redeemed <c>request_uri</c> — e.g. by clicking
/// "Continuar com esta conta" on a stale <c>/account/login</c> tab whose
/// session card links back to the consumed authorization request — the
/// validation pipeline rejects the request BEFORE the controller runs and
/// before any <c>redirect_uri</c> can be restored from the redeemed token
/// (the validation context is rejected, so OpenIddict's
/// <c>AttachRedirectUri</c> leaves <c>ApplyAuthorizationResponseContext.
/// RedirectUri</c> null). OpenIddict's terminal
/// <see cref="OpenIddictServerAspNetCoreHandlers.ProcessLocalErrorResponse{TContext}"/>
/// handler then writes a bare <c>text/plain</c> body
/// ("error:invalid_token ... already been redeemed"), which humans see raw.
///
/// This handler runs immediately before that terminal handler and, ONLY for
/// top-level browser navigations (<c>Accept: text/html</c>), replaces the raw
/// payload with a self-contained HTML page (no scripts, no styles, no remote
/// resources — CSP-safe under the host's same-origin policy). Machine clients
/// (no <c>text/html</c>) keep the protocol payload unchanged, and errors that
/// CAN be redirected to the RP are untouched: when
/// <c>context.RedirectUri</c> is set, OpenIddict's redirect machinery
/// (<c>ProcessQueryResponse</c>/<c>ProcessFragmentResponse</c>/
/// <c>ProcessFormPostResponse</c>) has already handled the transaction, so
/// silent renew (<c>prompt=none</c>) and normal code-flow errors continue to
/// be delivered to clients exactly as before.
/// </remarks>
internal static class BrowserAuthorizationErrorPage
{
    public sealed class RenderBrowserFriendlyAuthorizationError(
        ILogger<RenderBrowserFriendlyAuthorizationError> logger)
        : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
            OpenIddictServerHandlerDescriptor
                .CreateBuilder<OpenIddictServerEvents.ApplyAuthorizationResponseContext>()
                .AddFilter<OpenIddictServerAspNetCoreHandlerFilters.RequireHttpRequest>()
                .UseSingletonHandler<RenderBrowserFriendlyAuthorizationError>()
                .SetOrder(OpenIddictServerAspNetCoreHandlers
                    .ProcessLocalErrorResponse<OpenIddictServerEvents.ApplyAuthorizationResponseContext>
                    .Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(
            OpenIddictServerEvents.ApplyAuthorizationResponseContext context)
        {
            var response = context.Transaction.Response;

            // No protocol error on this response → nothing to humanize.
            if (response is null || string.IsNullOrEmpty(response.Error))
            {
                return;
            }

            // The error can still be delivered to the relying party — never
            // intercept it; OpenIddict's redirect machinery owns it.
            if (!string.IsNullOrEmpty(context.RedirectUri))
            {
                return;
            }

            var request = context.Transaction.GetHttpRequest();
            if (request is null)
            {
                return;
            }

            // Only humanize top-level browser navigations. Programmatic
            // clients (OAuth libraries, health probes, tests) must keep the
            // machine-readable payload.
            // Embedded UI owns eligible responses through status pages. This
            // renderer remains the fallback for hosts without that UI only.
            if (request.HttpContext.Features.Get<IStatusCodePagesFeature>()?.Enabled == true
                || !BrowserNavigationRequest.IsHtmlNavigation(request))
            {
                return;
            }

            var error = response.Error;
            var description = response.ErrorDescription;
            var errorUri = response.ErrorUri;

            logger.LogInformation(
                "Authorization endpoint error rendered as a browser page. "
                + "Error={Error}; TraceId={TraceId}.",
                error,
                request.HttpContext.TraceIdentifier);

            var heading = "Não foi possível concluir o acesso";
            var explanation = error switch
            {
                OpenIddictConstants.Errors.InvalidToken =>
                    """
                    O pedido de autorização que abriu esta tela já foi utilizado
                    ou expirou. Isso costuma acontecer quando a tela de login
                    fica aberta depois que o acesso já foi concluído, ou quando
                    o mesmo link é aberto uma segunda vez.
                    """,
                OpenIddictConstants.Errors.InvalidRequest =>
                    """
                    O pedido de autorização chegou incompleto ou inválido e não
                    pôde ser processado.
                    """,
                _ =>
                    """
                    O pedido de autorização não pôde ser processado.
                    """,
            };

            var html = new StringBuilder()
                .Append("<!doctype html><html lang=\"pt-BR\"><head>")
                .Append("<meta charset=\"utf-8\">")
                .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .Append("<meta name=\"robots\" content=\"noindex\">")
                .Append("<title>").Append(heading).Append(" — Sufficit Identity</title>")
                .Append("</head><body>")
                .Append("<main data-openiddict-error=\"")
                    .Append(HtmlEncoder.Default.Encode(error))
                    .Append("\">")
                .Append("<h1>").Append(heading).Append("</h1>")
                .Append("<p>").Append(explanation).Append("</p>")
                .Append("<p>Volte ao aplicativo de origem e inicie o acesso novamente. ")
                .Append("Se o problema persistir, entre em contato com o suporte informando os detalhes abaixo.</p>")
                .Append("<p><a href=\"/\">Ir para a página inicial</a></p>")
                .Append("<details><summary>Detalhes técnicos</summary><dl>");

            html.Append("<dt>error</dt><dd>")
                .Append(HtmlEncoder.Default.Encode(error))
                .Append("</dd>");
            if (!string.IsNullOrEmpty(description))
            {
                html.Append("<dt>error_description</dt><dd>")
                    .Append(HtmlEncoder.Default.Encode(description))
                    .Append("</dd>");
            }
            if (!string.IsNullOrEmpty(errorUri))
            {
                html.Append("<dt>error_uri</dt><dd>")
                    .Append(HtmlEncoder.Default.Encode(errorUri))
                    .Append("</dd>");
            }
            html.Append("<dt>trace_id</dt><dd>")
                .Append(HtmlEncoder.Default.Encode(request.HttpContext.TraceIdentifier))
                .Append("</dd>");

            html.Append("</dl></details></main></body></html>");

            var body = html.ToString();
            var httpResponse = request.HttpContext.Response;
            httpResponse.ContentType = "text/html; charset=utf-8";
            httpResponse.ContentLength = Encoding.UTF8.GetByteCount(body);
            await httpResponse.WriteAsync(body, context.CancellationToken);

            context.HandleRequest();
        }
    }
}
