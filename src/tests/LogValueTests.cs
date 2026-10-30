using Sufficit.Identity.Application.Diagnostics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class LogValueTests
{
    [Theory]
    [InlineData("client-a\r\nINFO forged entry", "client-aINFO forged entry")]
    [InlineData("a\nb\rc", "abc")]
    [InlineData("a\u0085b\u2028c\u2029d", "abcd")]
    [InlineData("plain-value", "plain-value")]
    public void Strips_line_breaks(string value, string expected)
        => Assert.Equal(expected, LogValue.Sanitize(value));

    [Fact]
    public void Keeps_null()
        => Assert.Null(LogValue.Sanitize(null));
}
