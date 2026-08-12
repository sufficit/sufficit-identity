using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.UI.Management.OperatorTokens;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class OperatorTokenRequestUrlTests
{
    [Fact]
    public void Build_replaces_capabilities_and_preserves_unrelated_parameters()
    {
        var navigation = new StubNavigationManager(
            "https://identity.sufficit.com.br/management/tokens"
            + "?culture=en-US&ui-culture=en-US"
            + "&purpose=Old&lifetimeSeconds=300"
            + "&capability=identity.users.read"
            + "&capabilities=identity.clients.read,identity.clients.update"
            + "&source=symposium#issuer");

        var result = OperatorTokenRequestUrl.Build(
            navigation,
            "  Review & deploy  ",
            900,
            [
                "identity.scopes.update",
                "identity.clients.read",
                "identity.scopes.update",
            ]);
        var uri = new Uri(result);
        var query = QueryHelpers.ParseQuery(uri.Query);

        Assert.Equal("issue", query["action"]);
        Assert.Equal("Review & deploy", query["purpose"]);
        Assert.Equal("900", query["lifetimeSeconds"]);
        Assert.Equal(2, query["capability"].Count);
        Assert.Equal("identity.clients.read", query["capability"][0]);
        Assert.Equal("identity.scopes.update", query["capability"][1]);
        Assert.False(query.ContainsKey("capabilities"));
        Assert.Equal("en-US", query["culture"]);
        Assert.Equal("en-US", query["ui-culture"]);
        Assert.Equal("symposium", query["source"]);
        Assert.Equal("#issuer", uri.Fragment);
    }

    [Fact]
    public void Build_removes_every_capability_parameter_when_selection_is_empty()
    {
        var navigation = new StubNavigationManager(
            "https://identity.sufficit.com.br/management/tokens"
            + "?capability=identity.users.read"
            + "&capabilities=identity.clients.read"
            + "&culture=pt-BR");

        var result = OperatorTokenRequestUrl.Build(
            navigation,
            "Operação temporária",
            600,
            []);
        var query = QueryHelpers.ParseQuery(new Uri(result).Query);

        Assert.False(query.ContainsKey("capability"));
        Assert.False(query.ContainsKey("capabilities"));
        Assert.Equal("pt-BR", query["culture"]);
        Assert.Equal("Operação temporária", query["purpose"]);
        Assert.Equal("600", query["lifetimeSeconds"]);
    }

    private sealed class StubNavigationManager : NavigationManager
    {
        public StubNavigationManager(string uri) => Initialize(
            "https://identity.sufficit.com.br/management/",
            uri);

        protected override void NavigateToCore(string uri, bool forceLoad) =>
            throw new NotSupportedException();
    }
}
