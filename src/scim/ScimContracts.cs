using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.Scim;

public static class ScimSchemas
{
    public const string User =
        "urn:ietf:params:scim:schemas:core:2.0:User";
    public const string Group =
        "urn:ietf:params:scim:schemas:core:2.0:Group";
    public const string ListResponse =
        "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public const string Error =
        "urn:ietf:params:scim:api:messages:2.0:Error";
    public const string PatchOperation =
        "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    public const string ServiceProviderConfig =
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
    public const string ResourceType =
        "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
    public const string Schema =
        "urn:ietf:params:scim:schemas:core:2.0:Schema";
}

public sealed class ScimMeta
{
    public string ResourceType { get; set; } = string.Empty;

    public DateTime Created { get; set; }

    public DateTime LastModified { get; set; }

    public string? Location { get; set; }
}

public sealed class ScimName
{
    public string? Formatted { get; set; }

    public string? FamilyName { get; set; }

    public string? GivenName { get; set; }

    public string? MiddleName { get; set; }

    public string? HonorificPrefix { get; set; }

    public string? HonorificSuffix { get; set; }
}

public sealed class ScimEmail
{
    public string Value { get; set; } = string.Empty;

    public string? Type { get; set; }

    public bool Primary { get; set; }
}

public sealed class ScimMember
{
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("$ref")]
    public string? Reference { get; set; }

    public string? Type { get; set; }

    public string? Display { get; set; }
}

public sealed class ScimUserResource
{
    public string[] Schemas { get; set; } = [ScimSchemas.User];

    public string? Id { get; set; }

    public string? ExternalId { get; set; }

    public string UserName { get; set; } = string.Empty;

    public ScimName? Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Title { get; set; }

    public string? UserType { get; set; }

    public string? PreferredLanguage { get; set; }

    public string? Locale { get; set; }

    public string? Timezone { get; set; }

    public bool Active { get; set; } = true;

    public IReadOnlyList<ScimEmail>? Emails { get; set; }

    public IReadOnlyList<ScimMember>? Groups { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Password { get; set; }

    public ScimMeta? Meta { get; set; }
}

public sealed class ScimGroupResource
{
    public string[] Schemas { get; set; } = [ScimSchemas.Group];

    public string? Id { get; set; }

    public string? ExternalId { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public IReadOnlyList<ScimMember> Members { get; set; } = [];

    public ScimMeta? Meta { get; set; }
}

public sealed class ScimListResponse<T>
{
    public string[] Schemas { get; set; } = [ScimSchemas.ListResponse];

    public int TotalResults { get; set; }

    public int StartIndex { get; set; }

    public int ItemsPerPage { get; set; }

    public IReadOnlyList<T> Resources { get; set; } = [];
}

public sealed class ScimPatchRequest
{
    public string[] Schemas { get; set; } = [ScimSchemas.PatchOperation];

    public IReadOnlyList<ScimPatchOperation> Operations { get; set; } = [];
}

public sealed class ScimPatchOperation
{
    public string Op { get; set; } = string.Empty;

    public string? Path { get; set; }

    public JsonElement Value { get; set; }
}

public sealed class ScimError
{
    public string[] Schemas { get; set; } = [ScimSchemas.Error];

    public string Status { get; set; } = string.Empty;

    public string? ScimType { get; set; }

    public string Detail { get; set; } = string.Empty;
}

public sealed class ScimException(
    int statusCode,
    string detail,
    string? scimType = null) : Exception(detail)
{
    public int StatusCode { get; } = statusCode;

    public string? ScimType { get; } = scimType;

    public static ScimException BadRequest(
        string detail,
        string? scimType = null) =>
        new(StatusCodes.Status400BadRequest, detail, scimType);

    public static ScimException NotFound(string detail) =>
        new(StatusCodes.Status404NotFound, detail);

    public static ScimException Conflict(string detail) =>
        new(StatusCodes.Status409Conflict, detail, "uniqueness");
}

public sealed record ScimRequestContext(
    System.Security.Claims.ClaimsPrincipal Principal,
    string CorrelationId)
{
    public string Actor =>
        Principal.FindFirst("client_id")?.Value
        ?? Principal.FindFirst("azp")?.Value
        ?? Principal.FindFirst("sub")?.Value
        ?? "scim-client";

    public string? AuthenticationMethods
    {
        get
        {
            var values = Principal.FindAll("amr")
                .SelectMany(claim => claim.Value.Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            return values.Length is 0 ? null : string.Join(' ', values);
        }
    }
}
