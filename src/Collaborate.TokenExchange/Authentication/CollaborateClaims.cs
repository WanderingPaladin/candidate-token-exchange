using System.Security.Claims;

namespace Collaborate.TokenExchange.Authentication;

/// <summary>
/// Claim type names used by this slice. Incoming JWT claim names are preserved
/// by setting <c>JwtBearerOptions.MapInboundClaims = false</c>.
/// </summary>
public static class CollaborateClaims
{
    public const string Subject = "sub";
    public const string AuthorizedParty = "azp";
    public const string ClientId = "client_id";
    public const string FirmId = "firm_id";
    public const string WorkspaceId = "workspace_id";
    public const string Scope = "scope";

    /// <summary>
    /// Acting client/service. A flat claim is used instead of RFC 8693's nested
    /// <c>act.sub</c> object so the attribution is obvious in tokens and tests.
    /// </summary>
    public const string ActorClientId = "actor_client_id";

    public static string? FindFirstNonEmpty(ClaimsPrincipal principal, params string[] claimTypes)
    {
        foreach (var claimType in claimTypes)
        {
            var value = principal.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    public static string? GetSubject(ClaimsPrincipal principal) =>
        FindFirstNonEmpty(principal, Subject, ClaimTypes.NameIdentifier);

    public static string? GetFirmId(ClaimsPrincipal principal) =>
        FindFirstNonEmpty(principal, FirmId);
}
