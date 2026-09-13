using Sufficit.Identity.STS.Email;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class EmailAddressRedactionTests
{
    [Theory]
    [InlineData("jane.doe@example.com", "j***@example.com")]
    [InlineData("  a@example.org ", "a***@example.org")]
    [InlineData("first@sub.example.net", "f***@sub.example.net")]
    public void Address_keeps_only_the_first_character_and_the_domain(
        string address,
        string expected) =>
        Assert.Equal(expected, EmailAddressRedaction.Mask(address));

    [Theory]
    [InlineData(null, "<empty>")]
    [InlineData("", "<empty>")]
    [InlineData("   ", "<empty>")]
    [InlineData("not-an-address", "***")]
    [InlineData("@example.com", "***")]
    [InlineData("user@", "***")]
    public void Malformed_values_never_echo_the_input(
        string? address,
        string expected) =>
        Assert.Equal(expected, EmailAddressRedaction.Mask(address));
}
