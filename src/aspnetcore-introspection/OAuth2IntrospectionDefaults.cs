namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Defaults shared by the handler and its registration.</summary>
public static class OAuth2IntrospectionDefaults
{
    /// <summary>Default authentication scheme name, the same one Duende uses.</summary>
    public const string AuthenticationScheme = "Bearer";

    /// <summary>Path appended to <see cref="OAuth2IntrospectionOptions.Authority"/> when no explicit endpoint is set.</summary>
    public const string IntrospectionPath = "/connect/introspect";

    /// <summary>Named <see cref="System.Net.Http.HttpClient"/> used for introspection calls.</summary>
    public const string HttpClientName = "Sufficit.Identity.OAuth2Introspection";

    /// <summary><see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/> key carrying an <see cref="IntrospectionUnavailableException"/>.</summary>
    public const string UnavailableItemKey = "Sufficit.Identity.OAuth2Introspection.Unavailable";
}
