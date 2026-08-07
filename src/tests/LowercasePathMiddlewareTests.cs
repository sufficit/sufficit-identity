using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class LowercasePathMiddlewareTests
{
    [Fact]
    public async Task Redirects_valid_uppercase_path_and_preserves_query_bytes()
    {
        var nextCalls = 0;
        var middleware = Middleware(() => nextCalls++);
        var context = Context(
            "/Account/Login",
            "?ReturnUrl=%2FConnect%2FAuthorize&State=AbC");

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status308PermanentRedirect, context.Response.StatusCode);
        Assert.Equal(
            "/account/login?ReturnUrl=%2FConnect%2FAuthorize&State=AbC",
            context.Response.Headers.Location.ToString());
        Assert.Equal(0, nextCalls);
    }

    [Fact]
    public async Task Preserves_path_base_when_building_the_local_redirect()
    {
        var nextCalls = 0;
        var middleware = Middleware(() => nextCalls++);
        var context = Context("/Account/Login");
        context.Request.PathBase = "/Identity";

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status308PermanentRedirect, context.Response.StatusCode);
        Assert.Equal("/Identity/account/login", context.Response.Headers.Location.ToString());
        Assert.Equal(0, nextCalls);
    }

    [Fact]
    public async Task Passes_an_already_canonical_local_path_to_the_next_component()
    {
        var nextCalls = 0;
        var middleware = Middleware(() => nextCalls++);
        var context = Context("/account/login");

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
        Assert.Equal(1, nextCalls);
    }

    [Theory]
    [InlineData("//evil.example/Login")]
    [InlineData("/\\evil.example/Login")]
    [InlineData("/%2Fevil.example/login")]
    [InlineData("/%2fevil.example/login")]
    [InlineData("/%5Cevil.example/login")]
    [InlineData("/%5cevil.example/login")]
    [InlineData("/%255Cevil.example/login")]
    public async Task Rejects_ambiguous_literal_and_encoded_request_paths(string path)
    {
        var nextCalls = 0;
        var middleware = Middleware(() => nextCalls++);
        var context = Context(path);

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
        Assert.Equal(0, nextCalls);
    }

    private static LowercasePathMiddleware Middleware(Action next) =>
        new(_ =>
        {
            next();
            return Task.CompletedTask;
        });

    private static DefaultHttpContext Context(string path, string? query = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.QueryString = new QueryString(query ?? string.Empty);
        return context;
    }
}
