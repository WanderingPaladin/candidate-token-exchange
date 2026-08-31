using System.Security.Claims;
using Collaborate.TokenExchange.Authentication;
using Collaborate.TokenExchange.Models;

namespace Collaborate.TokenExchange.Authorization;

public interface IDelegationAuthorizationService
{
    Task<DelegationDecision> AuthorizeAsync(
        ClaimsPrincipal user,
        TokenExchangeRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Decides whether a token exchange is legal. Does not issue tokens.
///
/// Effective delegated authority =
///     requested
///     ∩ user current authority
///     ∩ calling client authority
///     ∩ audience catalog
///     ∩ same-firm workspace policy
///
/// Any requested scope outside that intersection fails the whole request.
/// Silent partial grants would hide authorization bugs and make confused-deputy
/// failures look like success.
/// </summary>
public sealed class DelegationAuthorizationService : IDelegationAuthorizationService
{
    private readonly IPermissionService _permissions;
    private readonly IClientAuthorizationService _clients;
    private readonly IDownstreamAudienceRegistry _audiences;
    private readonly ICallingClientResolver _callingClientResolver;

    public DelegationAuthorizationService(
        IPermissionService permissions,
        IClientAuthorizationService clients,
        IDownstreamAudienceRegistry audiences,
        ICallingClientResolver callingClientResolver)
    {
        _permissions = permissions;
        _clients = clients;
        _audiences = audiences;
        _callingClientResolver = callingClientResolver;
    }

    public async Task<DelegationDecision> AuthorizeAsync(
        ClaimsPrincipal user,
        TokenExchangeRequest request,
        CancellationToken cancellationToken)
    {
        var audience = request.Audience?.Trim();
        var workspaceId = request.WorkspaceId?.Trim();
        var parsedScope = ScopeParser.Parse(request.Scope);

        if (string.IsNullOrWhiteSpace(audience))
        {
            return DelegationDecision.InvalidRequest(
                "invalid_request",
                "Audience is required.",
                DelegationDenialReasons.MissingAudience);
        }

        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            return DelegationDecision.InvalidRequest(
                "invalid_request",
                "Workspace is required.",
                DelegationDenialReasons.MissingWorkspace,
                audience: audience);
        }

        if (!parsedScope.IsValid)
        {
            return DelegationDecision.InvalidRequest(
                parsedScope.Error!,
                parsedScope.ErrorDescription!,
                DelegationDenialReasons.InvalidScope,
                workspaceId: workspaceId,
                audience: audience);
        }

        if (!_audiences.IsRegistered(audience) || !_audiences.TryGetAllowedScopes(audience, out var audienceScopes))
        {
            return DelegationDecision.InvalidRequest(
                "invalid_target",
                "The requested audience is not supported.",
                DelegationDenialReasons.UnknownAudience,
                workspaceId: workspaceId,
                audience: audience,
                requestedScopes: parsedScope.Scopes);
        }

        var subjectId = CollaborateClaims.GetSubject(user);
        var actorId = _callingClientResolver.GetClientId(user);
        var firmId = CollaborateClaims.GetFirmId(user);

        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return DelegationDecision.Forbidden(
                DelegationDenialReasons.MissingSubject,
                actorId: actorId,
                firmId: firmId,
                workspaceId: workspaceId,
                audience: audience,
                requestedScopes: parsedScope.Scopes);
        }

        if (string.IsNullOrWhiteSpace(actorId))
        {
            return DelegationDecision.Forbidden(
                DelegationDenialReasons.MissingClient,
                subjectId: subjectId,
                firmId: firmId,
                workspaceId: workspaceId,
                audience: audience,
                requestedScopes: parsedScope.Scopes);
        }

        if (string.IsNullOrWhiteSpace(firmId))
        {
            return DelegationDecision.Forbidden(
                DelegationDenialReasons.MissingFirm,
                subjectId: subjectId,
                actorId: actorId,
                workspaceId: workspaceId,
                audience: audience,
                requestedScopes: parsedScope.Scopes);
        }

        if (parsedScope.Scopes.Any(scope => !audienceScopes.Contains(scope)))
        {
            return DelegationDecision.InvalidRequest(
                "invalid_scope",
                "Requested scope is not available for this delegation.",
                DelegationDenialReasons.AudienceScopeMismatch,
                subjectId,
                actorId,
                firmId,
                workspaceId,
                audience,
                parsedScope.Scopes);
        }

        var evaluation = await _permissions.EvaluateAsync(subjectId, firmId, workspaceId, cancellationToken);
        if (evaluation.Status is PermissionStatus.UnknownWorkspace or PermissionStatus.None)
        {
            return DelegationDecision.Forbidden(
                evaluation.Status == PermissionStatus.UnknownWorkspace
                    ? DelegationDenialReasons.UnknownWorkspace
                    : DelegationDenialReasons.UserLacksScope,
                subjectId,
                actorId,
                firmId,
                workspaceId,
                audience,
                parsedScope.Scopes);
        }

        if (evaluation.Status == PermissionStatus.CrossFirm)
        {
            return DelegationDecision.Forbidden(
                DelegationDenialReasons.CrossFirm,
                subjectId,
                actorId,
                firmId,
                workspaceId,
                audience,
                parsedScope.Scopes);
        }

        var clientScopes = await _clients.GetAllowedScopesAsync(actorId, audience, cancellationToken);

        // Confused-deputy defense:
        // A privileged calling service must not use Alice's identity to exercise
        // authority Alice does not have, and Alice's broader grants must not let
        // a narrowly-registered client request more than it is allowed.
        // delegated scope ≠ user's total scope
        // delegated scope ≠ client's total scope
        foreach (var scope in parsedScope.Scopes)
        {
            if (!evaluation.Permissions.Contains(scope))
            {
                return DelegationDecision.Forbidden(
                    DelegationDenialReasons.UserLacksScope,
                    subjectId,
                    actorId,
                    firmId,
                    workspaceId,
                    audience,
                    parsedScope.Scopes);
            }

            if (!clientScopes.Contains(scope))
            {
                return DelegationDecision.Forbidden(
                    DelegationDenialReasons.ClientLacksScope,
                    subjectId,
                    actorId,
                    firmId,
                    workspaceId,
                    audience,
                    parsedScope.Scopes);
            }
        }

        return DelegationDecision.Allow(subjectId, actorId, audience, firmId, workspaceId, parsedScope.Scopes);
    }
}
