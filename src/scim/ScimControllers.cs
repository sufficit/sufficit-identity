using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Scim;

public abstract class ScimControllerBase : ControllerBase
{
    protected ObjectResult ScimOk(object value) =>
        ScimResult(value, StatusCodes.Status200OK);

    protected ObjectResult ScimCreated(object value) =>
        ScimResult(value, StatusCodes.Status201Created);

    protected ObjectResult ScimResult(object value, int statusCode)
    {
        var result = new ObjectResult(value)
        {
            StatusCode = statusCode
        };
        result.ContentTypes.Add("application/scim+json");
        return result;
    }

    protected ScimRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);

    protected string AbsoluteLocation(string relativePath) =>
        $"{Request.Scheme}://{Request.Host}{Request.PathBase}/{relativePath.TrimStart('/')}";

    protected void ApplyUserLocation(ScimUserResource resource)
    {
        if (resource.Meta is not null && resource.Id is not null)
        {
            resource.Meta.Location = AbsoluteLocation(
                $"scim/v2/users/{Uri.EscapeDataString(resource.Id)}");
        }
        if (resource.Groups is not null)
        {
            foreach (var group in resource.Groups)
            {
                group.Reference = AbsoluteLocation(
                    $"scim/v2/groups/{Uri.EscapeDataString(group.Value)}");
            }
        }
    }

    protected void ApplyGroupLocation(ScimGroupResource resource)
    {
        if (resource.Meta is not null && resource.Id is not null)
        {
            resource.Meta.Location = AbsoluteLocation(
                $"scim/v2/groups/{Uri.EscapeDataString(resource.Id)}");
        }
        foreach (var member in resource.Members)
        {
            var collection = string.Equals(
                member.Type,
                "Group",
                StringComparison.OrdinalIgnoreCase)
                    ? "groups"
                    : "users";
            member.Reference = AbsoluteLocation(
                $"scim/v2/{collection}/{Uri.EscapeDataString(member.Value)}");
        }
    }
}

[ApiController]
[Authorize(Policy = ScimServiceCollectionExtensions.PolicyName)]
[ServiceFilter(typeof(ScimExceptionFilter))]
[Route("scim/v2/users")]
public sealed class ScimUsersController(
    IScimProvisioningService provisioning) : ScimControllerBase
{
    [HttpGet]
    public async Task<ObjectResult> List(
        [FromQuery] string? filter,
        [FromQuery] int startIndex = 1,
        [FromQuery] int count = 100,
        CancellationToken cancellationToken = default)
    {
        var response = await provisioning.ListUsersAsync(
            filter,
            startIndex,
            count,
            RequestContext(),
            cancellationToken);
        foreach (var resource in response.Resources)
        {
            ApplyUserLocation(resource);
        }
        return ScimOk(response);
    }

    [HttpGet("{id}")]
    public async Task<ObjectResult> Get(
        string id,
        CancellationToken cancellationToken)
    {
        var resource = await provisioning.GetUserAsync(
            id,
            RequestContext(),
            cancellationToken);
        ApplyUserLocation(resource);
        return ScimOk(resource);
    }

    [HttpPost]
    public async Task<ObjectResult> Create(
        [FromBody] ScimUserResource resource,
        CancellationToken cancellationToken)
    {
        var created = await provisioning.CreateUserAsync(
            resource,
            RequestContext(),
            cancellationToken);
        ApplyUserLocation(created);
        Response.Headers.Location = created.Meta?.Location;
        return ScimCreated(created);
    }

    [HttpPut("{id}")]
    public async Task<ObjectResult> Replace(
        string id,
        [FromBody] ScimUserResource resource,
        CancellationToken cancellationToken)
    {
        var replaced = await provisioning.ReplaceUserAsync(
            id,
            resource,
            RequestContext(),
            cancellationToken);
        ApplyUserLocation(replaced);
        return ScimOk(replaced);
    }

    [HttpPatch("{id}")]
    public async Task<ObjectResult> Patch(
        string id,
        [FromBody] ScimPatchRequest request,
        CancellationToken cancellationToken)
    {
        var patched = await provisioning.PatchUserAsync(
            id,
            request,
            RequestContext(),
            cancellationToken);
        ApplyUserLocation(patched);
        return ScimOk(patched);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(
        string id,
        CancellationToken cancellationToken)
    {
        await provisioning.DeleteUserAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }
}

[ApiController]
[Authorize(Policy = ScimServiceCollectionExtensions.PolicyName)]
[ServiceFilter(typeof(ScimExceptionFilter))]
[Route("scim/v2/groups")]
public sealed class ScimGroupsController(
    IScimProvisioningService provisioning) : ScimControllerBase
{
    [HttpGet]
    public async Task<ObjectResult> List(
        [FromQuery] string? filter,
        [FromQuery] int startIndex = 1,
        [FromQuery] int count = 100,
        CancellationToken cancellationToken = default)
    {
        var response = await provisioning.ListGroupsAsync(
            filter,
            startIndex,
            count,
            RequestContext(),
            cancellationToken);
        foreach (var resource in response.Resources)
        {
            ApplyGroupLocation(resource);
        }
        return ScimOk(response);
    }

    [HttpGet("{id}")]
    public async Task<ObjectResult> Get(
        string id,
        CancellationToken cancellationToken)
    {
        var resource = await provisioning.GetGroupAsync(
            id,
            RequestContext(),
            cancellationToken);
        ApplyGroupLocation(resource);
        return ScimOk(resource);
    }

    [HttpPost]
    public async Task<ObjectResult> Create(
        [FromBody] ScimGroupResource resource,
        CancellationToken cancellationToken)
    {
        var created = await provisioning.CreateGroupAsync(
            resource,
            RequestContext(),
            cancellationToken);
        ApplyGroupLocation(created);
        Response.Headers.Location = created.Meta?.Location;
        return ScimCreated(created);
    }

    [HttpPut("{id}")]
    public async Task<ObjectResult> Replace(
        string id,
        [FromBody] ScimGroupResource resource,
        CancellationToken cancellationToken)
    {
        var replaced = await provisioning.ReplaceGroupAsync(
            id,
            resource,
            RequestContext(),
            cancellationToken);
        ApplyGroupLocation(replaced);
        return ScimOk(replaced);
    }

    [HttpPatch("{id}")]
    public async Task<ObjectResult> Patch(
        string id,
        [FromBody] ScimPatchRequest request,
        CancellationToken cancellationToken)
    {
        var patched = await provisioning.PatchGroupAsync(
            id,
            request,
            RequestContext(),
            cancellationToken);
        ApplyGroupLocation(patched);
        return ScimOk(patched);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(
        string id,
        CancellationToken cancellationToken)
    {
        await provisioning.DeleteGroupAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }
}

public sealed class ScimExceptionFilter(
    ILogger<ScimExceptionFilter> logger) : IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if (context.Exception is not ScimException exception)
        {
            logger.LogError(
                context.Exception,
                "Unhandled SCIM request failure. TraceIdentifier={TraceIdentifier}",
                context.HttpContext.TraceIdentifier);
            exception = new ScimException(
                StatusCodes.Status500InternalServerError,
                "The SCIM service could not complete the request.");
        }

        var result = new ObjectResult(new ScimError
        {
            Status = exception.StatusCode.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ScimType = exception.ScimType,
            Detail = exception.Message
        })
        {
            StatusCode = exception.StatusCode
        };
        result.ContentTypes.Add("application/scim+json");
        context.Result = result;
        context.ExceptionHandled = true;
    }
}
