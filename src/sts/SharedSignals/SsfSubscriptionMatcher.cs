using System.Text.Json;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS.SharedSignals;

internal interface ISsfSubscriptionMatcher
{
    bool Matches(SsfStream stream, string subject, string eventType);
}

internal sealed class SsfSubscriptionMatcher : ISsfSubscriptionMatcher
{
    public bool Matches(SsfStream stream, string subject, string eventType) =>
        EventMatches(stream.EventsRequested, eventType)
        && SubjectMatches(stream.SubjectScope, subject);

    private static bool EventMatches(string configuredEvents, string eventType)
    {
        try
        {
            using var document = JsonDocument.Parse(configuredEvents);
            if (document.RootElement.ValueKind != JsonValueKind.Array) return false;

            // Fail closed on an empty subscription. This previously returned
            // true (empty == "all supported events"), which meant a stream
            // created without events_requested silently received every CAEP
            // signal for every subject — the least specific request produced
            // the broadest delivery. A stream that subscribes to nothing now
            // receives nothing; creation-time validation rejects the empty
            // list up front so this state is not reachable for new streams.
            return document.RootElement.EnumerateArray().Any(
                item => item.ValueKind == JsonValueKind.String
                    && string.Equals(item.GetString(), eventType, StringComparison.Ordinal));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool SubjectMatches(string configuredSubject, string subject)
    {
        if (string.Equals(configuredSubject?.Trim(), "ALL", StringComparison.Ordinal))
            return true;
        if (string.Equals(configuredSubject?.Trim(), subject, StringComparison.Ordinal))
            return true;
        if (string.IsNullOrWhiteSpace(configuredSubject)) return false;

        try
        {
            using var document = JsonDocument.Parse(configuredSubject);
            return SubjectElementMatches(document.RootElement, subject);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool SubjectElementMatches(JsonElement element, string subject) =>
        element.ValueKind switch
        {
            JsonValueKind.String => string.Equals(
                element.GetString(), subject, StringComparison.Ordinal),
            JsonValueKind.Array => element.EnumerateArray()
                .Any(item => SubjectElementMatches(item, subject)),
            JsonValueKind.Object => ObjectSubjectMatches(element, subject),
            _ => false,
        };

    private static bool ObjectSubjectMatches(JsonElement element, string subject)
    {
        foreach (var propertyName in new[] { "sub", "id", "subject" })
        {
            if (element.TryGetProperty(propertyName, out var value)
                && value.ValueKind == JsonValueKind.String
                && string.Equals(value.GetString(), subject, StringComparison.Ordinal))
                return true;
        }

        return false;
    }
}
