using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Components;
using Sufficit.Identity.UI.Management.Resources;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The single result-state component of the Management console (E5): every
/// outcome renders its own state and recovery, the region is announced, and
/// an empty success stays distinguishable from a failure.
/// </summary>
public sealed class ManagementDataViewTests : IDisposable
{
    private readonly BunitContext context = new();
    private readonly IStringLocalizer<ManagementResource> localizer;

    public ManagementDataViewTests()
    {
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddLocalization();
        context.Services.AddSingleton<AntiforgeryStateProvider, FixedAntiforgeryStateProvider>();
        localizer = context.Services
            .GetRequiredService<IStringLocalizer<ManagementResource>>();
    }

    public void Dispose() => context.Dispose();

    [Fact]
    public void Loading_renders_the_skeleton_inside_a_busy_live_region()
    {
        var cut = Render(result: null, loading: true);

        var region = cut.Find(".management-data-view");
        Assert.Equal("polite", region.GetAttribute("aria-live"));
        Assert.Equal("true", region.GetAttribute("aria-busy"));
        Assert.Equal("loading", region.GetAttribute("data-outcome"));
        Assert.NotNull(cut.Find(".table-skeleton"));
        Assert.Empty(cut.FindAll(".management-data-state"));
        Assert.Empty(cut.FindAll(".items"));
    }

    [Fact]
    public void A_missing_result_is_still_loading()
    {
        var cut = Render(result: null, loading: false);

        Assert.Equal("true", cut.Find(".management-data-view").GetAttribute("aria-busy"));
        Assert.NotNull(cut.Find(".table-skeleton"));
    }

    [Fact]
    public void Custom_loading_content_replaces_the_default_skeleton()
    {
        var cut = context.Render<ManagementDataView<IReadOnlyList<string>>>(parameters => parameters
            .Add(view => view.Loading, true)
            .Add(view => view.LoadingContent, (RenderFragment)(builder =>
                builder.AddMarkupContent(0, "<p class=\"custom-loading\">wait</p>")))
            .Add(view => view.Success, (RenderFragment<IReadOnlyList<string>>)(_ => _ => { })));

        Assert.NotNull(cut.Find(".custom-loading"));
        Assert.Empty(cut.FindAll(".table-skeleton"));
    }

    [Fact]
    public void Success_renders_the_page_fragment_and_clears_busy()
    {
        var cut = Render(ManagementDataResult<IReadOnlyList<string>>.Success(["a", "b"]));

        var region = cut.Find(".management-data-view");
        Assert.Equal("false", region.GetAttribute("aria-busy"));
        Assert.Equal("success", region.GetAttribute("data-outcome"));
        Assert.Equal(2, cut.FindAll(".items li").Count);
        Assert.Empty(cut.FindAll(".management-data-state"));
    }

    [Fact]
    public void Success_with_an_empty_collection_is_not_a_failure()
    {
        var empty = Render(ManagementDataResult<IReadOnlyList<string>>.Success([]));
        var failed = Render(ManagementDataResult<IReadOnlyList<string>>.Failure(
            ManagementDataOutcome.Unavailable));

        // The page composes its own empty state inside Success...
        Assert.NotNull(empty.Find(".page-empty"));
        Assert.Equal("success", empty.Find(".management-data-view").GetAttribute("data-outcome"));
        Assert.Empty(empty.FindAll(".management-data-state"));
        Assert.DoesNotContain(localizer["Common.State.Retry"].Value, empty.Markup);

        // ...while a failure never reaches the page fragment.
        Assert.Empty(failed.FindAll(".page-empty"));
        Assert.Equal("unavailable", failed.Find(".management-data-view").GetAttribute("data-outcome"));
        Assert.NotNull(failed.Find(".management-data-state"));
    }

    [Fact]
    public void A_success_without_a_value_is_presented_as_unavailable()
    {
        var cut = Render(new ManagementDataResult<IReadOnlyList<string>>(
            ManagementDataOutcome.Success));

        Assert.Equal("unavailable", cut.Find(".management-data-view").GetAttribute("data-outcome"));
        Assert.Contains(localizer["Common.State.Unavailable.Title"].Value, cut.Markup);
    }

    [Theory]
    [InlineData(ManagementDataOutcome.Forbidden, "forbidden", "Common.State.Forbidden.Title", "Common.Access.Forbidden", false)]
    [InlineData(ManagementDataOutcome.StepUpRequired, "step-up-required", "Common.State.StepUp.Title", "Common.Access.StepUpRequired", false)]
    [InlineData(ManagementDataOutcome.Unavailable, "unavailable", "Common.State.Unavailable.Title", "Common.Unavailable", true)]
    [InlineData(ManagementDataOutcome.NotFound, "not-found", "Common.State.NotFound.Title", "Common.State.NotFound.Description", false)]
    [InlineData(ManagementDataOutcome.Invalid, "invalid", "Common.State.Invalid.Title", "Common.Unavailable", true)]
    [InlineData(ManagementDataOutcome.Conflict, "conflict", "Common.State.Conflict.Title", "Common.Unavailable", true)]
    public void Each_failure_renders_its_canonical_state(
        ManagementDataOutcome outcome,
        string name,
        string titleKey,
        string fallbackDescriptionKey,
        bool retryable)
    {
        Assert.False(localizer[titleKey].ResourceNotFound, titleKey);
        Assert.False(localizer[fallbackDescriptionKey].ResourceNotFound, fallbackDescriptionKey);
        var cut = Render(ManagementDataResult<IReadOnlyList<string>>.Failure(outcome));

        Assert.Equal(name, cut.Find(".management-data-view").GetAttribute("data-outcome"));
        Assert.Equal(localizer[titleKey].Value, cut.Find(".sui-empty__title").TextContent);
        Assert.Equal(
            localizer[fallbackDescriptionKey].Value,
            cut.Find(".sui-empty__description").TextContent);
        Assert.Empty(cut.FindAll(".items"));
        Assert.Equal(
            retryable,
            cut.FindAll("button").Any(button =>
                button.TextContent.Trim() == localizer["Common.State.Retry"].Value));
    }

    [Theory]
    [InlineData(ManagementDataOutcome.Forbidden)]
    [InlineData(ManagementDataOutcome.StepUpRequired)]
    [InlineData(ManagementDataOutcome.Unavailable)]
    [InlineData(ManagementDataOutcome.NotFound)]
    [InlineData(ManagementDataOutcome.Invalid)]
    [InlineData(ManagementDataOutcome.Conflict)]
    public void The_service_message_is_shown_when_present(ManagementDataOutcome outcome)
    {
        var cut = Render(ManagementDataResult<IReadOnlyList<string>>.Failure(
            outcome,
            "The name 'x' is already in use."));

        Assert.Equal(
            "The name 'x' is already in use.",
            cut.Find(".sui-empty__description").TextContent);
    }

    [Fact]
    public void Retry_invokes_the_page_callback()
    {
        var retries = 0;
        var cut = Render(
            ManagementDataResult<IReadOnlyList<string>>.Failure(ManagementDataOutcome.Unavailable),
            onRetry: () => retries++);

        cut.Find("button").Click();

        Assert.Equal(1, retries);
    }

    [Fact]
    public void Retry_is_not_offered_without_a_callback()
    {
        var cut = context.Render<ManagementDataView<IReadOnlyList<string>>>(parameters => parameters
            .Add(view => view.Result, ManagementDataResult<IReadOnlyList<string>>.Failure(
                ManagementDataOutcome.Unavailable))
            .Add(view => view.Success, (RenderFragment<IReadOnlyList<string>>)(_ => _ => { })));

        Assert.Empty(cut.FindAll("button"));
    }

    [Fact]
    public void Step_up_sends_the_operator_to_sign_in_again_with_mfa()
    {
        var cut = Render(ManagementDataResult<IReadOnlyList<string>>.Failure(
            ManagementDataOutcome.StepUpRequired));

        var form = cut.Find("form");
        Assert.Equal("post", form.GetAttribute("method"));
        Assert.Equal("/connect/endsession", form.GetAttribute("action"));
        Assert.Equal("false", form.GetAttribute("data-enhance"));
        Assert.Equal("true", cut.Find("input[name=force_mfa]").GetAttribute("value"));
        Assert.NotNull(cut.Find("input[name=__RequestVerificationToken]"));
        Assert.Contains(localizer["Common.State.StepUp.Action"].Value, form.TextContent);
    }

    [Fact]
    public void Page_wording_overrides_the_canonical_title_only_for_its_outcome()
    {
        var forbidden = Render(
            ManagementDataResult<IReadOnlyList<string>>.Failure(ManagementDataOutcome.Forbidden),
            configure: parameters => parameters
                .Add(view => view.ForbiddenTitle, "Directory access denied")
                .Add(view => view.UnavailableTitle, "Could not load the users"));
        var unavailable = Render(
            ManagementDataResult<IReadOnlyList<string>>.Failure(ManagementDataOutcome.Unavailable),
            configure: parameters => parameters
                .Add(view => view.ForbiddenTitle, "Directory access denied")
                .Add(view => view.UnavailableTitle, "Could not load the users"));

        Assert.Equal("Directory access denied", forbidden.Find(".sui-empty__title").TextContent);
        Assert.Equal("Could not load the users", unavailable.Find(".sui-empty__title").TextContent);
    }

    [Fact]
    public void Failure_actions_and_container_class_frame_the_failure_only()
    {
        var cut = Render(
            ManagementDataResult<IReadOnlyList<string>>.Failure(ManagementDataOutcome.NotFound),
            configure: parameters => parameters
                .Add(view => view.FailureClass, "panel")
                .Add(view => view.FailureActions, (RenderFragment)(builder =>
                    builder.AddMarkupContent(0, "<a class=\"back\" href=\"users\">Back</a>"))));

        Assert.NotNull(cut.Find(".panel .management-data-state"));
        Assert.NotNull(cut.Find(".management-data-state a.back"));

        var success = Render(
            ManagementDataResult<IReadOnlyList<string>>.Success(["a"]),
            configure: parameters => parameters.Add(view => view.FailureClass, "panel"));
        Assert.Empty(success.FindAll(".panel"));
    }

    private IRenderedComponent<ManagementDataView<IReadOnlyList<string>>> Render(
        ManagementDataResult<IReadOnlyList<string>>? result,
        bool loading = false,
        Action? onRetry = null,
        Action<ComponentParameterCollectionBuilder<ManagementDataView<IReadOnlyList<string>>>>? configure = null) =>
        context.Render<ManagementDataView<IReadOnlyList<string>>>(parameters =>
        {
            parameters
                .Add(view => view.Result, result)
                .Add(view => view.Loading, loading)
                .Add(view => view.OnRetry, onRetry ?? (() => { }))
                .Add(view => view.Success, (RenderFragment<IReadOnlyList<string>>)(items => builder =>
                {
                    if (items.Count is 0)
                    {
                        builder.AddMarkupContent(0, "<div class=\"page-empty\">No items yet</div>");
                        return;
                    }

                    builder.OpenElement(1, "ul");
                    builder.AddAttribute(2, "class", "items");
                    foreach (var item in items)
                    {
                        builder.OpenElement(3, "li");
                        builder.AddContent(4, item);
                        builder.CloseElement();
                    }

                    builder.CloseElement();
                }));
            configure?.Invoke(parameters);
        });

    private sealed class FixedAntiforgeryStateProvider : AntiforgeryStateProvider
    {
        public override AntiforgeryRequestToken? GetAntiforgeryToken() =>
            new("test-token", "__RequestVerificationToken");
    }
}
