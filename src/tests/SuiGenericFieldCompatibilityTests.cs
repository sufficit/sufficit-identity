using Xunit;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.UI.Components;

namespace Sufficit.Identity.Tests;

public sealed class SuiGenericFieldCompatibilityTests
{
    [Fact]
    public async Task Text_field_preserves_value_callback_and_rendering()
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        await using var renderer = new HtmlRenderer(services, services.GetRequiredService<ILoggerFactory>());
        var captured = "";
        var callback = EventCallback.Factory.Create<string>(new object(), value => captured = value);
        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var output = await renderer.RenderComponentAsync<IdentityTextField<string>>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                {
                    ["Value"] = "current value", ["ValueChanged"] = callback,
                    ["InputType"] = "password", ["Id"] = "recovery-password"
                }));
            return output.ToHtmlString();
        });
        Assert.Contains("<input", html);
        Assert.Contains("current value", html);
        Assert.Contains("type=\"password\"", html);
        await callback.InvokeAsync("new value");
        Assert.Equal("new value", captured);
    }
}
