using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Unified DbContext for the STS:
///   - ASP.NET Core Identity tables (users, roles, claims, logins, ...)
///   - OpenIddict tables (applications, authorizations, scopes, tokens)
///   - ASP.NET Core Data Protection key ring (dataprotectionkeys)
///
/// All tables and columns follow the Sufficit naming convention:
/// lowercase with underscores (snake_case), no prefixes.
/// </summary>
public sealed class AppDbContext
    : IdentityDbContext<ApplicationUser, ApplicationRole, string,
        IdentityUserClaim<string>, IdentityUserRole<string>,
        IdentityUserLogin<string>, IdentityRoleClaim<string>,
        IdentityUserToken<string>, IdentityUserPasskey<string>>, IDataProtectionKeyContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    /// <summary>
    /// Backing store for <c>services.AddDataProtection().PersistKeysToDbContext&lt;AppDbContext&gt;()</c>
    /// (see AddSufficitIdentitySTS in ServiceCollectionExtensions.cs, P0 #B4).
    /// Without this, the Data Protection key ring defaults to the local
    /// filesystem, so every container restart or additional replica
    /// regenerates it — invalidating in-flight auth cookies, antiforgery
    /// tokens and ASP.NET Identity reset/confirmation tokens.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    /// <summary>
    /// Branding themes for the Sufficit Identity UI. Only one record should
    /// have IsActive = true. Cached by <c>BrandingThemeProvider</c>.
    /// </summary>
    public DbSet<Entities.BrandingTheme> BrandingThemes => Set<Entities.BrandingTheme>();

    /// <summary>
    /// Append-only administrative authorization and mutation audit trail.
    /// </summary>
    public DbSet<Entities.ManagementAuditEvent> ManagementAuditEvents =>
        Set<Entities.ManagementAuditEvent>();

    public DbSet<Entities.ManagementClientDraftRecord> ManagementClientDrafts =>
        Set<Entities.ManagementClientDraftRecord>();

    public DbSet<Entities.ScimUserProfile> ScimUserProfiles =>
        Set<Entities.ScimUserProfile>();

    public DbSet<Entities.ScimGroup> ScimGroups =>
        Set<Entities.ScimGroup>();

    public DbSet<Entities.ScimGroupUserMember> ScimGroupUserMembers =>
        Set<Entities.ScimGroupUserMember>();

    public DbSet<Entities.ScimGroupGroupMember> ScimGroupGroupMembers =>
        Set<Entities.ScimGroupGroupMember>();

    /// <summary>SSF stream configuration (RFC 8933).</summary>
    public DbSet<Entities.SsfStream> SsfStreams =>
        Set<Entities.SsfStream>();

    /// <summary>Queued SETs awaiting poll delivery (RFC 8934).</summary>
    public DbSet<Entities.SsfSetDelivery> SsfSetDeliveries =>
        Set<Entities.SsfSetDelivery>();

    /// <summary>
    /// Durable server-side browser sessions for the ASP.NET Core Identity
    /// application cookie (the <c>ITicketStore</c> backing
    /// <c>CookieAuthenticationOptions.SessionStore</c>). One row per active
    /// SSO session, keyed by the OIDC <c>sid</c>.
    /// </summary>
    public DbSet<Entities.OidcUserSession> OidcUserSessions =>
        Set<Entities.OidcUserSession>();

    /// <summary>
    /// Wrapped vault keys (DEKs / item keys) for the internal secret vault.
    /// Key material is never stored unwrapped (the KEK unwraps at runtime).
    /// </summary>
    public DbSet<Entities.VaultKey> VaultKeys =>
        Set<Entities.VaultKey>();

    public DbSet<Entities.VaultSigningKeyLifecycleOperation>
        VaultSigningKeyLifecycleOperations =>
        Set<Entities.VaultSigningKeyLifecycleOperation>();

    public DbSet<Entities.VaultSigningKeyLock> VaultSigningKeyLocks =>
        Set<Entities.VaultSigningKeyLock>();

    /// <summary>
    /// Optional named secrets (Phase 2). Values are always vault ciphertext;
    /// this table contains no plaintext secret material.
    /// </summary>
    public DbSet<Entities.VaultSecret> VaultSecrets =>
        Set<Entities.VaultSecret>();

    public DbSet<Entities.IdentityMetricsConfiguration> IdentityMetricsConfigurations =>
        Set<Entities.IdentityMetricsConfiguration>();

    public DbSet<Entities.IdentityApplicationUsageEvent> IdentityApplicationUsageEvents =>
        Set<Entities.IdentityApplicationUsageEvent>();

    public DbSet<Entities.DpopReplayEntry> DpopReplayEntries =>
        Set<Entities.DpopReplayEntry>();

    public DbSet<Entities.CibaPendingState> CibaPendingStates =>
        Set<Entities.CibaPendingState>();

    /// <summary>
    /// Durable protocol state that has no table of its own (DPoP nonces,
    /// front-channel logout context, passkey ceremony tickets).
    /// </summary>
    public DbSet<Entities.ProtocolStateEntry> ProtocolStateEntries =>
        Set<Entities.ProtocolStateEntry>();

    /// <summary>
    /// Multiple independently revocable credentials for OAuth clients. This
    /// store deliberately uses client_id instead of an OpenIddict foreign key
    /// so the credential lifecycle survives a future protocol-engine swap.
    /// </summary>
    public DbSet<Entities.OAuthClientCredential> OAuthClientCredentials =>
        Set<Entities.OAuthClientCredential>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        IdentityTablesMapping.Apply(builder);
        OpenIddictTablesMapping.Apply(builder);
        DataProtectionMapping.Apply(builder);
        PasskeyMapping.Apply(builder);
        BrandingMapping.Apply(builder);
        ManagementAuditMapping.Apply(builder);
        ManagementClientDraftMapping.Apply(builder);
        ScimMapping.Apply(builder);
        SsfStreamMapping.Apply(builder);
        OidcUserSessionMapping.Apply(builder);
        VaultKeyMapping.Apply(builder);
        VaultSecretMapping.Apply(builder);
        IdentityMetricsMapping.Apply(builder);
        ProtocolSecurityStateMapping.Apply(builder);
        OAuthClientCredentialMapping.Apply(builder);

        // F-3 (eval 2026-08-14): opaque CSPRNG identifiers are matched by
        // equality and must not fold case. Applied only under MySQL/MariaDB —
        // the SQLite test host has no MariaDB collations.
        if (Database.IsMySql())
        {
            OpaqueIdentifierCollationMapping.Apply(builder);
        }
    }

}
