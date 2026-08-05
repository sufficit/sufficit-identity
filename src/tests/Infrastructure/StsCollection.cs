using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Shares a single <see cref="SufficitIdentityTestFactory"/> (and its one
/// SQLite in-memory connection) across every test class in the suite, seeded
/// once. Placing all test classes in this collection also makes xUnit run
/// them sequentially against the shared database instead of in parallel,
/// which the single, held-open SQLite connection does not support safely.
/// </summary>
[CollectionDefinition(Name)]
public sealed class StsCollection : ICollectionFixture<SufficitIdentityTestFactory>
{
    public const string Name = "Sufficit Identity STS";
}
