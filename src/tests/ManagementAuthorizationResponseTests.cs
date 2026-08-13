using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Scim;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementAuthorizationResponseTests
{
    [Fact]
    public async Task Missing_management_scope_returns_actionable_problem_details()
    {
        var requirement = new ScopeRequirement("identity.management");
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(requirement)
            .Build();
        var context = Context("management-scope-test");
        var result = PolicyAuthorizationResult.Forbid(
            AuthorizationFailure.Failed([requirement]));

        await new ManagementAuthorizationMiddlewareResultHandler()
            .HandleAsync(_ => Task.CompletedTask, context, policy, result);

        var body = await ReadBodyAsync(context);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.Equal(
            "application/problem+json; charset=utf-8",
            context.Response.ContentType);
        Assert.Equal(
            "scope_required",
            body.GetProperty("reasonCode").GetString());
        Assert.Equal(
            "identity.management",
            body.GetProperty("requiredPermission").GetString());
        Assert.Equal(
            "management-scope-test",
            body.GetProperty("correlationId").GetString());
    }

    [Fact]
    public async Task Missing_mfa_returns_specific_problem_details()
    {
        var requirement = new MfaRequirement();
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(requirement)
            .Build();
        var context = Context("management-mfa-test");
        var result = PolicyAuthorizationResult.Forbid(
            AuthorizationFailure.Failed([requirement]));

        await new ManagementAuthorizationMiddlewareResultHandler()
            .HandleAsync(_ => Task.CompletedTask, context, policy, result);

        var body = await ReadBodyAsync(context);
        Assert.Equal(
            "mfa_required",
            body.GetProperty("reasonCode").GetString());
        Assert.False(body.TryGetProperty("requiredPermission", out _));
        Assert.Contains(
            "segundo fator",
            body.GetProperty("detail").GetString(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Composed_handler_keeps_management_problem_details()
    {
        var requirement = new ScopeRequirement("identity.management");
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(requirement)
            .Build();
        var context = Context("composed-management-test");
        var result = PolicyAuthorizationResult.Forbid(
            AuthorizationFailure.Failed([requirement]));
        var handler = new SufficitIdentityAuthorizationMiddlewareResultHandler(
            new ManagementAuthorizationMiddlewareResultHandler(),
            new ScimAuthorizationAuditHandler());

        await handler.HandleAsync(
            _ => Task.CompletedTask,
            context,
            policy,
            result);

        var body = await ReadBodyAsync(context);
        Assert.Equal(
            "scope_required",
            body.GetProperty("reasonCode").GetString());
        Assert.Equal(
            "identity.management",
            body.GetProperty("requiredPermission").GetString());
    }

    [Fact]
    public async Task Capability_denial_identifies_the_required_permission()
    {
        var evaluator = new CapabilityManagementAuthorizationEvaluator(
            Microsoft.Extensions.Options.Options.Create(
                new ManagementOptions()));
        var principal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                authenticationType: "test"));

        var decision = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.UserCollection));

        Assert.Equal("capability_not_granted", decision.ReasonCode);
        Assert.Equal(
            ManagementCapabilities.UsersRead,
            decision.RequiredCapability);
    }

    private static DefaultHttpContext Context(string traceIdentifier)
    {
        var context = new DefaultHttpContext
        {
            TraceIdentifier = traceIdentifier
        };
        context.Request.Path = "/api/users";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<JsonElement> ReadBodyAsync(
        DefaultHttpContext context)
    {
        context.Response.Body.Position = 0;
        using var document = await JsonDocument.ParseAsync(
            context.Response.Body);
        return document.RootElement.Clone();
    }
}
