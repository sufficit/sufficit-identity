namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// Which presentation surface a UI module provides.
/// </summary>
public enum UiSurface
{
    /// <summary>The public-facing login/consent/device/manage UI.</summary>
    Public = 0,

    /// <summary>The operator management UI.</summary>
    Management = 1,
}

/// <summary>
/// Identity + compatibility metadata for a composed UI module. Registered by
/// each <c>AddSufficitIdentity*UI</c> method so the host can validate the
/// composition at startup (Phase 2): reject duplicates, incompatible versions,
/// and missing dependencies.
/// </summary>
public sealed record UiModuleDescriptor(
    string Id,
    UiSurface Surface,
    Version Version,
    Version MinHostVersion);
