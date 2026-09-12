namespace Sufficit.Identity.STS.Resources;

/// <summary>
/// Marker type for end-user text that the API module renders itself — email
/// messages and the fallback browser error page — because no presentation
/// layer sits between the server and the reader.
/// </summary>
/// <remarks>
/// <para>
/// Everything else the API returns is English plus a stable machine code, and
/// the presentation module localizes by that code. Keeping user languages out
/// of API responses is what lets any front end, in any language, consume the
/// same endpoints.
/// </para>
/// <para>
/// <c>AccountMessages.resx</c> is the English neutral resource;
/// <c>AccountMessages.pt-BR.resx</c> and any culture a deployment adds are
/// satellites selected by the request culture.
/// </para>
/// </remarks>
public sealed class AccountMessages
{
}
