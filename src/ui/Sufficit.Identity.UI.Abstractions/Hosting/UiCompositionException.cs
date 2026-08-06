namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// Thrown when the UI composition is invalid at startup (duplicate module,
/// incompatible version, missing dependency, or surface requested without a
/// module).
/// </summary>
public sealed class UiCompositionException(string message) : Exception(message);
