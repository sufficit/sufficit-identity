using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using System.Security.Cryptography;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientConfigurationDraftService
{
    private async Task<ClientDraftValidation> ValidateAsync(
        ManagementClientDraftValues values,
        CancellationToken cancellationToken)
    {
        var issues = new List<ClientValidationIssue>();
        AddRequired(issues, values.DisplayName, "display_name_required",
            ManagementClientDraftSteps.Identity, "displayName",
            "Informe um nome que permita reconhecer a aplicação.");
        AddRequired(issues, values.ClientId, "client_id_required",
            ManagementClientDraftSteps.Identity, "clientId",
            "Informe um client ID estável para a integração.");

        var clientId = values.ClientId.Trim();
        if (clientId.Length > IdentityDatabaseSchema.OpenIddictClientIdLength)
        {
            AddError(issues, "client_id_too_long", ManagementClientDraftSteps.Identity,
                "clientId", $"Use no máximo {IdentityDatabaseSchema.OpenIddictClientIdLength} caracteres.");
        }
        else if (clientId.Length > 0 && clientId.Any(char.IsWhiteSpace))
        {
            issues.Add(new ClientValidationIssue(
                "client_id_whitespace",
                ManagementClientDraftSteps.Identity,
                "clientId",
                ClientValidationSeverity.Warning,
                "Espaços no client ID dificultam integrações e diagnóstico.",
                "Prefira letras, números, ponto, hífen, sublinhado ou dois-pontos."));
        }

        if (clientId.Length > 0 && await applications.FindByClientIdAsync(
                clientId,
                cancellationToken) is not null)
        {
            AddError(issues, "client_already_exists", ManagementClientDraftSteps.Identity,
                "clientId", "Este client ID já pertence a outra aplicação.");
        }

        var grants = GrantCount(values);
        if (grants == 0)
        {
            AddError(issues, "grant_required", ManagementClientDraftSteps.Protocol,
                "grantTypes", "Escolha como a aplicação irá obter tokens.");
        }
        if (values.ClientCredentials &&
            string.Equals(values.ClientType, "public", StringComparison.Ordinal))
        {
            AddError(issues, "confidential_client_required", ManagementClientDraftSteps.Protocol,
                "clientType", "Client Credentials exige uma aplicação confidencial.");
        }
        if (values.AuthorizationCode && values.RedirectUris.Count == 0)
        {
            AddError(issues, "redirect_uri_required", ManagementClientDraftSteps.Uris,
                "redirectUris", "O login interativo exige pelo menos uma Redirect URI.");
        }
        if (values.Scopes.Contains("offline_access", StringComparer.Ordinal) && !values.RefreshToken)
        {
            AddError(issues, "offline_access_requires_refresh_token",
                ManagementClientDraftSteps.Permissions, "scopes",
                "offline_access exige que Refresh Token esteja habilitado.");
        }

        ValidateOptionalLifetime(issues, values.AccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumAccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumAccessTokenLifetimeMinutes,
            "accessTokenLifetimeMinutes", "Access token deve ficar entre 1 minuto e 7 dias.");
        ValidateOptionalLifetime(issues, values.IdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumIdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumIdentityTokenLifetimeMinutes,
            "identityTokenLifetimeMinutes", "ID token deve ficar entre 1 e 120 minutos.");
        ValidateOptionalLifetime(issues, values.RefreshTokenLifetimeDays,
            TokenLifetimeLimits.MinimumRefreshTokenLifetimeDays,
            TokenLifetimeLimits.MaximumRefreshTokenLifetimeDays,
            "refreshTokenLifetimeDays", "Refresh token deve ficar entre 1 e 365 dias.");

        if (values.ClientCredentials && !values.AuthorizationCode && !values.DeviceCode)
        {
            foreach (var scope in values.Scopes.Where(IsUserIdentityScope))
            {
                AddError(issues, "identity_scope_without_user",
                    ManagementClientDraftSteps.Permissions, "scopes",
                    $"O scope '{scope}' representa um usuário e não se aplica a serviço para serviço.");
            }
        }

        ValidateUris(issues, values.RedirectUris, "redirectUris");
        ValidateUris(issues, values.PostLogoutRedirectUris, "postLogoutRedirectUris");
        ValidateOptionalUri(issues, values.FrontchannelLogoutUri, "frontchannelLogoutUri");
        ValidateOptionalUri(issues, values.BackchannelLogoutUri, "backchannelLogoutUri");
        if (TryAbsoluteUri(values.FrontchannelLogoutUri, out var frontchannelUri)
            && !values.RedirectUris
                .Select(value => TryAbsoluteUri(value, out var redirectUri) ? redirectUri : null)
                .Any(redirectUri => redirectUri is not null && SameOrigin(redirectUri, frontchannelUri)))
        {
            AddError(issues, "frontchannel_logout_origin_mismatch",
                ManagementClientDraftSteps.Uris, "frontchannelLogoutUri",
                "A URI de front-channel deve usar o mesmo protocolo, host e porta de uma Redirect URI.");
        }
        if (values.FrontchannelLogoutSessionRequired &&
            string.IsNullOrWhiteSpace(values.FrontchannelLogoutUri))
        {
            AddError(issues, "frontchannel_logout_uri_required", ManagementClientDraftSteps.Uris,
                "frontchannelLogoutUri", "Informe a URI antes de exigir logout por sessão.");
        }
        if (values.BackchannelLogoutSessionRequired &&
            string.IsNullOrWhiteSpace(values.BackchannelLogoutUri))
        {
            AddError(issues, "backchannel_logout_uri_required", ManagementClientDraftSteps.Uris,
                "backchannelLogoutUri", "Informe a URI antes de exigir logout por sessão.");
        }

        return new ClientDraftValidation(
            issues.All(issue => issue.Severity is not ClientValidationSeverity.Error),
            issues);
    }

    private static void ValidateUris(
        ICollection<ClientValidationIssue> issues,
        IReadOnlyList<string> values,
        string field)
    {
        foreach (var value in values)
        {
            ValidateOptionalUri(issues, value, field);
        }

        var duplicates = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .GroupBy(value => value.Trim(), StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);
        foreach (var duplicate in duplicates)
        {
            AddError(issues, "redirect_uri_duplicate", ManagementClientDraftSteps.Uris,
                field, $"A URI '{duplicate}' aparece mais de uma vez.");
        }
    }

    private static void ValidateOptionalUri(
        ICollection<ClientValidationIssue> issues,
        string? value,
        string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            AddError(issues, "redirect_uri_invalid", ManagementClientDraftSteps.Uris,
                field, $"'{value}' não é uma URI absoluta válida.");
            return;
        }
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            AddError(issues, "redirect_uri_fragment", ManagementClientDraftSteps.Uris,
                field, "Redirect URIs não podem conter fragmento (#...).");
        }
        var loopback = uri.IsLoopback || string.Equals(
            uri.Host,
            "localhost",
            StringComparison.OrdinalIgnoreCase);
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !loopback)
        {
            AddError(issues, "redirect_uri_https_required", ManagementClientDraftSteps.Uris,
                field, "Use HTTPS. HTTP é aceito somente em loopback local.");
        }
    }

    private static bool TryAbsoluteUri(string? value, out Uri uri)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && Uri.TryCreate(value.Trim(), UriKind.Absolute, out var parsed))
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }

    private static void ValidateOptionalLifetime(
        ICollection<ClientValidationIssue> issues,
        int? value,
        int minimum,
        int maximum,
        string field,
        string message)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            AddError(issues, $"{field}_invalid", ManagementClientDraftSteps.Protocol,
                field, message);
        }
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static void AddRequired(
        ICollection<ClientValidationIssue> issues,
        string? value,
        string code,
        string step,
        string field,
        string message)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddError(issues, code, step, field, message);
        }
    }

    private static void AddError(
        ICollection<ClientValidationIssue> issues,
        string code,
        string step,
        string field,
        string message) =>
        issues.Add(new ClientValidationIssue(
            code,
            step,
            field,
            ClientValidationSeverity.Error,
            message));

    private static bool IsUserIdentityScope(string scope) =>
        scope is "openid" or "profile" or "email" or "phone" or "address" or "roles";

    private static int GrantCount(ManagementClientDraftValues values) =>
        (values.AuthorizationCode ? 1 : 0)
        + (values.RefreshToken ? 1 : 0)
        + (values.ClientCredentials ? 1 : 0)
        + (values.DeviceCode ? 1 : 0);
}
