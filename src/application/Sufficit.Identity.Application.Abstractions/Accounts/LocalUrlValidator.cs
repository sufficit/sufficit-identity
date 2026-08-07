namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Validates caller-supplied return URLs before navigation or HTTP redirects.
/// </summary>
public static class LocalUrlValidator
{
    public static string EnsureLocal(string? url, string fallback = "/") =>
        IsLocal(url) ? url! : fallback;

    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Check local path syntax before Uri.TryCreate: .NET treats a path
        // such as `/connect/authorize?client_id=...` as an absolute `file:`
        // URI, which would otherwise discard valid OIDC return URLs.
        if (url[0] == '/')
        {
            return url.Length == 1
                || !IsAmbiguousRootSeparator(url, 1);
        }

        if (url[0] == '~')
        {
            return url.Length > 1
                && url[1] == '/'
                && (url.Length == 2
                    || !IsAmbiguousRootSeparator(url, 2));
        }

        return false;
    }

    private static bool IsAmbiguousRootSeparator(string url, int index)
    {
        var current = url[index];
        if (current is '/' or '\\')
        {
            return true;
        }

        // A server/proxy/browser may decode the request target at a different
        // layer. Treat encoded and repeatedly encoded root separators exactly
        // like their literal form so every redirect caller gets one stable
        // decision from this validator.
        var implicitPercent = false;
        for (var depth = 0; depth < 3; depth++)
        {
            int encoded;
            if (implicitPercent)
            {
                if (index + 1 >= url.Length
                    || !TryDecodeHexByte(url[index], url[index + 1], out encoded))
                {
                    return false;
                }

                index += 2;
            }
            else
            {
                if (url[index] != '%'
                    || index + 2 >= url.Length
                    || !TryDecodeHexByte(url[index + 1], url[index + 2], out encoded))
                {
                    return false;
                }

                index += 3;
            }

            if (encoded is '/' or '\\')
            {
                return true;
            }

            if (encoded != '%')
            {
                return false;
            }

            implicitPercent = true;
        }

        return false;
    }

    private static bool TryDecodeHexByte(char high, char low, out int value)
    {
        var highValue = HexValue(high);
        var lowValue = HexValue(low);
        if (highValue < 0 || lowValue < 0)
        {
            value = 0;
            return false;
        }

        value = highValue * 16 + lowValue;
        return true;
    }

    private static int HexValue(char value) => value switch
    {
        >= '0' and <= '9' => value - '0',
        >= 'A' and <= 'F' => value - 'A' + 10,
        >= 'a' and <= 'f' => value - 'a' + 10,
        _ => -1,
    };
}
