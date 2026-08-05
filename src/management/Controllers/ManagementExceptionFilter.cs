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
                Title = "Invalid identity provisioning manifest",
                Detail = "No database changes were made.",
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
                    "Invalid management request",
                    validation.Message,
                    validation.ReasonCode,
                    validation.Field),
            ManagementConflictException conflict =>
                (StatusCodes.Status409Conflict,
                    "Management resource conflict",
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
                    "Additional authentication required",
                    "Multi-factor authentication is required for this operation.",
                    access.Decision.ReasonCode,
                    (string?)null),
            ManagementAccessException access =>
                (StatusCodes.Status403Forbidden,
                    "Management operation forbidden",
                    "The operator does not have the required capability.",
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
}
