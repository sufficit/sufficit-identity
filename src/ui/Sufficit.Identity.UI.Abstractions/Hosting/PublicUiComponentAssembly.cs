using System.Reflection;

namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// A component assembly that joins the public UI's Blazor endpoint instead of
/// mapping its own. Register one per assembly through dependency injection;
/// the public UI reads every registration when it maps its endpoint, so the
/// contributing surface and the public UI never reference each other.
/// </summary>
public sealed record PublicUiComponentAssembly(Assembly Assembly);
