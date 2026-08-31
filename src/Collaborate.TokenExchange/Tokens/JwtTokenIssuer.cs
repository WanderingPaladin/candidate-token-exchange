using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Collaborate.TokenExchange.Authentication;
using Collaborate.TokenExchange.Authorization;
using Collaborate.TokenExchange.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Tokens;

public interface ITokenIssuer
{
    IssuedToken Issue(DelegationDecision decision);
}

public sealed record IssuedToken(string AccessToken, int ExpiresInSeconds, string Scope);

/// <summary>
/// Issues a short-lived downstream JWT from an already-approved delegation.
/// This is a targeted demonstration, not an authorization server.
/// Tokens are built with Microsoft.IdentityModel — no custom cryptography.
/// </summary>
public sealed class JwtTokenIssuer : ITokenIssuer
{
    private readonly TokenExchangeOptions _options;
    private readonly ISigningCredentialProvider _signing;
    private readonly TimeProvider _timeProvider;

    public JwtTokenIssuer(
        IOptions<TokenExchangeOptions> options,
        ISigningCredentialProvider signing,
        TimeProvider timeProvider)
    {
        _options = options.Value;
        _signing = signing;
        _timeProvider = timeProvider;
    }

    public IssuedToken Issue(DelegationDecision decision)
    {
        if (!decision.Allowed)
        {
            throw new InvalidOperationException("Refusing to issue a token for a denied delegation.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(decision.SubjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(decision.ActorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(decision.Audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(decision.FirmId);
        ArgumentException.ThrowIfNullOrWhiteSpace(decision.WorkspaceId);

        var lifetime = TimeSpan.FromMinutes(_options.DelegatedTokenLifetimeMinutes);
        var now = _timeProvider.GetUtcNow();
        var expires = now.Add(lifetime);
        var scope = string.Join(' ', decision.GrantedScopes);

        // Deliberate minimal claim set. Incoming claims are not copied.
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(CollaborateClaims.Subject, decision.SubjectId),
            new(CollaborateClaims.ActorClientId, decision.ActorId),
            new(CollaborateClaims.FirmId, decision.FirmId),
            new(CollaborateClaims.WorkspaceId, decision.WorkspaceId),
            new(CollaborateClaims.Scope, scope)
        };

        var payload = new JwtPayload(
            issuer: _options.OutgoingIssuer,
            audience: decision.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            issuedAt: now.UtcDateTime);

        var token = new JwtSecurityToken(new JwtHeader(_signing.GetSigningCredentials()), payload);
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return new IssuedToken(jwt, (int)lifetime.TotalSeconds, scope);
    }
}
