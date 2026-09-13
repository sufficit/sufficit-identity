using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Controllers;

internal sealed class ManagementExceptionFilter : IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if (context.Exception is IdentityProvisioningManifestException manifest)
        {
            var manifestDetails = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Invalid provisioning manifest",
                Detail = "Fix the fields listed in errors. No changes were made to the database.",
                Instance = context.HttpContext.Request.Path
            };
            manifestDetails.Extensions["reasonCode"] =
                "provisioning_manifest_invalid";
            manifestDetails.Extensions["correlationId"] =
                context.HttpContext.TraceIdentifier;
            manifestDetails.Extensions["errors"] = manifest.Errors;
            context.Result = new ObjectResult(manifestDetails)
            {
                StatusCode = StatusCodes.Status400BadRequest
            };
            context.ExceptionHandled = true;
            return;
        }

        var mapping = context.Exception switch
        {
            ManagementValidationException validation =>
                (StatusCodes.Status400BadRequest,
                    "Invalid Management request",
                    validation.Message,
                    validation.ReasonCode,
                    validation.Field),
            ManagementConflictException conflict =>
                (StatusCodes.Status409Conflict,
                    "Configuration prevents the operation",
                    conflict.Message,
                    conflict.ReasonCode,
                    (string?)null),
            ManagementNotFoundException notFound =>
                (StatusCodes.Status404NotFound,
                    "Management resource not found",
                    notFound.Message,
                    notFound.ReasonCode,
                    (string?)null),
            ManagementAccessException access
                when access.Decision.Outcome is
                    ManagementAuthorizationOutcome.StepUpRequired =>
                (StatusCodes.Status403Forbidden,
                    "MFA required to continue",
                    "The session is authenticated, but has not yet proven MFA. Complete the second factor and repeat the operation.",
                    access.Decision.ReasonCode,
                    (string?)null),
            ManagementAccessException access =>
                (StatusCodes.Status403Forbidden,
                    "Missing required capability",
                    AccessDetail(access.Decision),
                    access.Decision.ReasonCode,
                    (string?)null),
            _ => default
        };

        if (mapping == default)
        {
            return;
        }

        var details = new ProblemDetails
        {
            Status = mapping.Item1,
            Title = mapping.Item2,
            Detail = mapping.Item3,
            Instance = context.HttpContext.Request.Path
        };
        details.Extensions["reasonCode"] = mapping.Item4;
        details.Extensions["correlationId"] =
            context.HttpContext.TraceIdentifier;
        if (context.Exception is ManagementAccessException accessException
            && !string.IsNullOrWhiteSpace(
                accessException.Decision.RequiredCapability))
        {
            details.Extensions["requiredPermission"] =
                accessException.Decision.RequiredCapability;
        }
        if (mapping.Item5 is not null)
        {
            details.Extensions["field"] = mapping.Item5;
        }

        context.Result = new ObjectResult(details)
        {
            StatusCode = mapping.Item1
        };
        context.ExceptionHandled = true;
    }

    private static string AccessDetail(
        ManagementAuthorizationDecision decision) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                "There is no authenticated session. Sign in to Management and repeat the operation.",
            "capability_not_granted" =>
                "The session is authenticated, but the operator has not been granted the capability required by the operation.",
            _ => "The operation was blocked by an Identity authorization rule. Check reasonCode and correlationId for diagnostics."
        };
}
