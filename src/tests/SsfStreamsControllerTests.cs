using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Controllers;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SsfStreamsControllerTests
{
    [Fact]
    public async Task Create_rejects_omitted_event_list()
    {
        var controller = CreateController(requireExplicitSubject: false);

        var result = await controller.Create(
            new SsfStreamsController.CreateStreamRequest
            {
                Audience = "https://receiver.tests.local/events",
                EventsRequested = null,
            },
            CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = JsonSerializer.SerializeToElement(badRequest.Value);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
        Assert.Contains(
            "events_requested must list at least one event type",
            body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task Create_rejects_empty_event_list()
    {
        var controller = CreateController(requireExplicitSubject: false);

        var result = await controller.Create(
            new SsfStreamsController.CreateStreamRequest
            {
                Audience = "https://receiver.tests.local/events",
                EventsRequested = [],
            },
            CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Create_rejects_omitted_subject_when_policy_requires_it()
    {
        var controller = CreateController(requireExplicitSubject: true);

        var result = await controller.Create(
            new SsfStreamsController.CreateStreamRequest
            {
                Audience = "https://receiver.tests.local/events",
                EventsRequested = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
                Subject = null,
            },
            CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = JsonSerializer.SerializeToElement(badRequest.Value);
        Assert.Contains(
            "subject must be supplied explicitly",
            body.GetProperty("error_description").GetString());
    }

    private static SsfStreamsController CreateController(bool requireExplicitSubject)
    {
        var controller = new SsfStreamsController(
            store: null!,
            generator: null!,
            httpClientFactory: null!,
            NullLogger<SsfStreamsController>.Instance,
            new SufficitIdentityOptions
            {
                SharedSignals = new SharedSignalsOptions
                {
                    RequireExplicitSubject = requireExplicitSubject,
                },
            });

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim(OpenIddictConstants.Claims.ClientId, "receiver-client")],
                    authenticationType: "test")),
            },
        };

        return controller;
    }
}
