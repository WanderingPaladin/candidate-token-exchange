using System.Collections.Frozen;

namespace Collaborate.TokenExchange.Authorization;

/// <summary>
/// Parses space-separated OAuth scopes. Values are trimmed and compared
/// exactly — OAuth scopes are case-sensitive, so we do not lowercase them.
/// </summary>
public static class ScopeParser
{
    public static readonly FrozenSet<string> RecognizedScopes = new[]
    {
        "documents.read",
        "documents.write",
        "comments.read",
        "comments.write",
        "financial.read"
    }.ToFrozenSet(StringComparer.Ordinal);

    public static ScopeParseResult Parse(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return ScopeParseResult.Invalid("invalid_scope", "Scope is required.");
        }

        var parts = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
        {
            return ScopeParseResult.Invalid("invalid_scope", "Scope is required.");
        }

        var unique = new List<string>(parts.Length);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var part in parts)
        {
            if (!RecognizedScopes.Contains(part))
            {
                return ScopeParseResult.Invalid(
                    "invalid_scope",
                    "Requested scope is not available for this delegation.");
            }

            if (!seen.Add(part))
            {
                return ScopeParseResult.Invalid(
                    "invalid_scope",
                    "Duplicate scopes are not allowed.");
            }

            unique.Add(part);
        }

        return ScopeParseResult.Valid(unique);
    }
}

public sealed record ScopeParseResult(
    bool IsValid,
    IReadOnlyList<string> Scopes,
    string? Error,
    string? ErrorDescription)
{
    public static ScopeParseResult Valid(IReadOnlyList<string> scopes) =>
        new(true, scopes, null, null);

    public static ScopeParseResult Invalid(string error, string description) =>
        new(false, [], error, description);
}
