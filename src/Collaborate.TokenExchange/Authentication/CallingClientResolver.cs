using System.Security.Claims;

namespace Collaborate.TokenExchange.Authentication;

/// <summary>
/// Resolves the calling application/service from the validated token.
/// The request body is never consulted — a client id supplied only in JSON
/// would allow a caller to impersonate another registered client.
/// </summary>
public interface ICallingClientResolver
{
    string? GetClientId(ClaimsPrincipal principal);
}

public sealed class CallingClientResolver : ICallingClientResolver
{
    public string? GetClientId(ClaimsPrincipal principal) =>
        CollaborateClaims.FindFirstNonEmpty(
            principal,
            CollaborateClaims.AuthorizedParty,
            CollaborateClaims.ClientId);
}
