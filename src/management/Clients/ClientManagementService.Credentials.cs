using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using System.Globalization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    // Credential and mTLS certificate lifecycle lives in its own type; these
    // stay on the interface so controllers and the embedded UI are unaffected
    // by the split.
    public Task<ManagementClientCredentialsOverview> GetCredentialsAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.GetCredentialsAsync(clientId, context, cancellationToken);

    public Task<CreateManagementClientCredentialResult> CreateCredentialAsync(
        CreateManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.CreateCredentialAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RevokeCredentialAsync(
        RevokeManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RevokeCredentialAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RegisterTlsCertificateAsync(
        RegisterManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RegisterTlsCertificateAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RevokeTlsCertificateAsync(
        RevokeManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RevokeTlsCertificateAsync(command, context, cancellationToken);
}
