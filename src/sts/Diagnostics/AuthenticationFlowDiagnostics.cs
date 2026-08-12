using System.Diagnostics;

namespace Sufficit.Identity.STS;

/// <summary>
/// Small, non-sensitive correlation helper for authentication-flow logs.
/// Never carries credentials, cookies, TOTP values or token contents.
/// </summary>
internal static class AuthenticationFlowDiagnostics
{
    public static string TraceId =>
        Activity.Current?.TraceId.ToString() ?? "none";
}
