using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document):
/// an HTTPS client_id resolved on first use into a public PKCE client.
/// </summary>
internal sealed class ClientIdMetadataDocumentProtocolFeature : IProtocolFeature
{
    public string Name => "client-id-metadata-documents";

    public bool IsEnabled(SufficitIdentityOptions options) =>
        options.Mcp.ClientIdMetadataDocuments.Enabled;

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        discovery.Metadata["client_id_metadata_document_supported"] =
            JsonValue.Create(context.Options.Mcp.ClientIdMetadataDocuments.Enabled);
    }
}
