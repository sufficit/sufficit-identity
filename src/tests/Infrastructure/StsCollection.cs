using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Shares a single <see cref="SufficitIdentityTestFactory"/> and its temporary
/// SQLite database across every test class in the suite, seeded once. Placing
/// all test classes in this collection keeps independent scenarios sequential,
/// while each request context still uses its own database connection so an
/// individual test can exercise intentional protocol races safely.
/// </summary>
[CollectionDefinition(Name)]
public sealed class StsCollection : ICollectionFixture<SufficitIdentityTestFactory>
{
    public const string Name = "Sufficit Identity STS";
}
