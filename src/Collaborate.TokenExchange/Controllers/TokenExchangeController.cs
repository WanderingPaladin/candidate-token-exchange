using Collaborate.TokenExchange.Authorization;
using Collaborate.TokenExchange.Models;
using Collaborate.TokenExchange.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Collaborate.TokenExchange.Controllers;

[ApiController]
[Authorize]
[Route("oauth/token")]
public sealed class TokenExchangeController : ControllerBase
{
    private readonly IDelegationAuthorizationService _authorization;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly ILogger<TokenExchangeController> _logger;

    public TokenExchangeController(
        IDelegationAuthorizationService authorization,
        ITokenIssuer tokenIssuer,
        ILogger<TokenExchangeController> logger)
    {
        _authorization = authorization;
        _tokenIssuer = tokenIssuer;
        _logger = logger;
    }

    [HttpPost("exchange")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange(
        [FromBody] TokenExchangeRequest request,
        CancellationToken cancellationToken)
    {
        var decision = await _authorization.AuthorizeAsync(User, request, cancellationToken);
        LogDecision(decision);

        if (!decision.Allowed)
        {
            var error = new OAuthErrorResponse
            {
                Error = decision.Error ?? "access_denied",
                ErrorDescription = decision.ErrorDescription ?? "Delegation is not authorized."
            };

            return decision.FailureKind == DelegationFailureKind.InvalidRequest
                ? BadRequest(error)
                : StatusCode(StatusCodes.Status403Forbidden, error);
        }

        var issued = _tokenIssuer.Issue(decision);

        return Ok(new TokenExchangeResponse
        {
            AccessToken = issued.AccessToken,
            ExpiresIn = issued.ExpiresInSeconds,
            Scope = issued.Scope
        });
    }

    private void LogDecision(DelegationDecision decision)
    {
        if (decision.Allowed)
        {
            _logger.LogInformation(
                "Token exchange allowed. Subject={Subject} Actor={Actor} Firm={Firm} Workspace={Workspace} Audience={Audience} Scopes={Scopes} TraceId={TraceId}",
                decision.SubjectId,
                decision.ActorId,
                decision.FirmId,
                decision.WorkspaceId,
                decision.Audience,
                string.Join(' ', decision.GrantedScopes),
                HttpContext.TraceIdentifier);
            return;
        }

        _logger.LogInformation(
            "Token exchange denied. Subject={Subject} Actor={Actor} Audience={Audience} Scopes={Scopes} Reason={Reason} TraceId={TraceId}",
            decision.SubjectId,
            decision.ActorId,
            decision.Audience,
            string.Join(' ', decision.RequestedScopes),
            decision.DenialReason,
            HttpContext.TraceIdentifier);
    }
}
