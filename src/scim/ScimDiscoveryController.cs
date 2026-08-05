using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.Scim;

[ApiController]
[Authorize(Policy = ScimServiceCollectionExtensions.PolicyName)]
[ServiceFilter(typeof(ScimExceptionFilter))]
[Route("scim/v2")]
public sealed class ScimDiscoveryController(
    IOptions<ScimOptions> options) : ScimControllerBase
{
    [HttpGet("service-provider-config")]
    public ObjectResult ServiceProviderConfig() =>
        ScimOk(new Dictionary<string, object?>
        {
            ["schemas"] = new[] { ScimSchemas.ServiceProviderConfig },
            ["documentationUri"] =
                "https://www.rfc-editor.org/rfc/rfc7644.html",
            ["patch"] = new { supported = true },
            ["bulk"] = new
            {
                supported = false,
                maxOperations = 0,
                maxPayloadSize = 0
            },
            ["filter"] = new
            {
                supported = true,
                maxResults = Math.Clamp(options.Value.MaxResults, 1, 1000)
            },
            ["changePassword"] = new { supported = true },
            ["sort"] = new { supported = false },
            ["etag"] = new { supported = false },
            ["authenticationSchemes"] = new[]
            {
                new
                {
                    type = "oauthbearertoken",
                    name = "OAuth Bearer Token",
                    description =
                        "OAuth 2.0 bearer token carrying the configured SCIM scope.",
                    specUri =
                        "https://www.rfc-editor.org/rfc/rfc6750.html",
                    primary = true
                }
            },
            ["meta"] = new
            {
                resourceType = "ServiceProviderConfig",
                location = AbsoluteLocation(
                    "scim/v2/service-provider-config")
            }
        });

    [HttpGet("resource-types")]
    public ObjectResult ResourceTypes() =>
        ScimOk(new ScimListResponse<object>
        {
            TotalResults = 2,
            StartIndex = 1,
            ItemsPerPage = 2,
            Resources =
            [
                UserResourceType(),
                GroupResourceType()
            ]
        });

    [HttpGet("resource-types/{id}")]
    public ObjectResult ResourceType(string id) =>
        id.ToLowerInvariant() switch
        {
            "user" => ScimOk(UserResourceType()),
            "group" => ScimOk(GroupResourceType()),
            _ => throw ScimException.NotFound(
                $"SCIM resource type '{id}' was not found.")
        };

    [HttpGet("schemas")]
    public ObjectResult Schemas() =>
        ScimOk(new ScimListResponse<object>
        {
            TotalResults = 2,
            StartIndex = 1,
            ItemsPerPage = 2,
            Resources =
            [
                UserSchema(),
                GroupSchema()
            ]
        });

    [HttpGet("schemas/{id}")]
    public ObjectResult Schema(string id) =>
        id switch
        {
            ScimSchemas.User => ScimOk(UserSchema()),
            ScimSchemas.Group => ScimOk(GroupSchema()),
            _ => throw ScimException.NotFound(
                $"SCIM schema '{id}' was not found.")
        };

    private Dictionary<string, object?> UserResourceType() =>
        new()
        {
            ["schemas"] = new[] { ScimSchemas.ResourceType },
            ["id"] = "User",
            ["name"] = "User",
            ["endpoint"] = "/users",
            ["description"] = "Identity account",
            ["schema"] = ScimSchemas.User,
            ["schemaExtensions"] = Array.Empty<object>(),
            ["meta"] = new
            {
                resourceType = "ResourceType",
                location = AbsoluteLocation(
                    "scim/v2/resource-types/User")
            }
        };

    private Dictionary<string, object?> GroupResourceType() =>
        new()
        {
            ["schemas"] = new[] { ScimSchemas.ResourceType },
            ["id"] = "Group",
            ["name"] = "Group",
            ["endpoint"] = "/groups",
            ["description"] =
                "Opaque provisioning group without provider-role semantics",
            ["schema"] = ScimSchemas.Group,
            ["schemaExtensions"] = Array.Empty<object>(),
            ["meta"] = new
            {
                resourceType = "ResourceType",
                location = AbsoluteLocation(
                    "scim/v2/resource-types/Group")
            }
        };

    private Dictionary<string, object?> UserSchema() =>
        new()
        {
            ["schemas"] = new[] { ScimSchemas.Schema },
            ["id"] = ScimSchemas.User,
            ["name"] = "User",
            ["description"] = "SCIM core user schema",
            ["attributes"] = new object[]
            {
                Attribute("userName", "string", required: true,
                    uniqueness: "server"),
                Attribute("externalId", "string"),
                Attribute(
                    "name",
                    "complex",
                    subAttributes:
                    [
                        Attribute("formatted", "string"),
                        Attribute("familyName", "string"),
                        Attribute("givenName", "string"),
                        Attribute("middleName", "string"),
                        Attribute("honorificPrefix", "string"),
                        Attribute("honorificSuffix", "string")
                    ]),
                Attribute("displayName", "string"),
                Attribute("title", "string"),
                Attribute("userType", "string"),
                Attribute("preferredLanguage", "string"),
                Attribute("locale", "string"),
                Attribute("timezone", "string"),
                Attribute("active", "boolean"),
                Attribute(
                    "password",
                    "string",
                    mutability: "writeOnly",
                    returned: "never"),
                Attribute(
                    "emails",
                    "complex",
                    multiValued: true,
                    subAttributes:
                    [
                        Attribute("value", "string"),
                        Attribute("type", "string"),
                        Attribute("primary", "boolean")
                    ]),
                Attribute(
                    "groups",
                    "complex",
                    multiValued: true,
                    mutability: "readOnly",
                    returned: "default",
                    subAttributes:
                    [
                        Attribute("value", "string"),
                        Attribute("$ref", "reference"),
                        Attribute("display", "string", mutability: "readOnly"),
                        Attribute("type", "string", mutability: "readOnly")
                    ])
            },
            ["meta"] = new
            {
                resourceType = "Schema",
                location = AbsoluteLocation(
                    $"scim/v2/schemas/{ScimSchemas.User}")
            }
        };

    private Dictionary<string, object?> GroupSchema() =>
        new()
        {
            ["schemas"] = new[] { ScimSchemas.Schema },
            ["id"] = ScimSchemas.Group,
            ["name"] = "Group",
            ["description"] = "SCIM core group schema",
            ["attributes"] = new object[]
            {
                Attribute("displayName", "string", required: true),
                Attribute("externalId", "string"),
                Attribute(
                    "members",
                    "complex",
                    multiValued: true,
                    subAttributes:
                    [
                        Attribute("value", "string"),
                        Attribute("$ref", "reference"),
                        Attribute("type", "string"),
                        Attribute("display", "string", mutability: "readOnly")
                    ])
            },
            ["meta"] = new
            {
                resourceType = "Schema",
                location = AbsoluteLocation(
                    $"scim/v2/schemas/{ScimSchemas.Group}")
            }
        };

    private static Dictionary<string, object?> Attribute(
        string name,
        string type,
        bool multiValued = false,
        bool required = false,
        string mutability = "readWrite",
        string returned = "default",
        string uniqueness = "none",
        object[]? subAttributes = null) =>
        new()
        {
            ["name"] = name,
            ["type"] = type,
            ["multiValued"] = multiValued,
            ["description"] = name,
            ["required"] = required,
            ["caseExact"] = false,
            ["mutability"] = mutability,
            ["returned"] = returned,
            ["uniqueness"] = uniqueness,
            ["subAttributes"] = subAttributes
        };
}
