namespace Sufficit.Identity.STS.Email;

/// <summary>
/// Masks email addresses before they are written to logs. The first
/// character and the domain remain, which is enough to correlate delivery
/// problems with a provider without recording the full personal address.
/// </summary>
public static class EmailAddressRedaction
{
    public static string Mask(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return "<empty>";
        }

        var trimmed = address.Trim();
        var at = trimmed.LastIndexOf('@');
        if (at <= 0 || at == trimmed.Length - 1)
        {
            return "***";
        }

        return trimmed[0] + "***" + trimmed[at..];
    }
}
