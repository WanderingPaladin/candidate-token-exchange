namespace Collaborate.TokenExchange.Authorization;

public enum DelegationFailureKind
{
    None,
    InvalidRequest,
    Forbidden
}

public sealed record DelegationDecision
{
    public required bool Allowed { get; init; }

    public DelegationFailureKind FailureKind { get; init; }

    public string? Error { get; init; }

    public string? ErrorDescription { get; init; }

    /// <summary>High-level denial code that is safe to log (no secrets).</summary>
    public string? DenialReason { get; init; }

    public string? SubjectId { get; init; }

    public string? ActorId { get; init; }

    public string? Audience { get; init; }

    public string? FirmId { get; init; }

    public string? WorkspaceId { get; init; }

    public IReadOnlyList<string> GrantedScopes { get; init; } = [];

    public IReadOnlyList<string> RequestedScopes { get; init; } = [];

    public static DelegationDecision Allow(
        string subjectId,
        string actorId,
        string audience,
        string firmId,
        string workspaceId,
        IReadOnlyList<string> grantedScopes) =>
        new()
        {
            Allowed = true,
            FailureKind = DelegationFailureKind.None,
            SubjectId = subjectId,
            ActorId = actorId,
            Audience = audience,
            FirmId = firmId,
            WorkspaceId = workspaceId,
            GrantedScopes = grantedScopes,
            RequestedScopes = grantedScopes
        };

    public static DelegationDecision InvalidRequest(
        string error,
        string errorDescription,
        string denialReason,
        string? subjectId = null,
        string? actorId = null,
        string? firmId = null,
        string? workspaceId = null,
        string? audience = null,
        IReadOnlyList<string>? requestedScopes = null) =>
        new()
        {
            Allowed = false,
            FailureKind = DelegationFailureKind.InvalidRequest,
            Error = error,
            ErrorDescription = errorDescription,
            DenialReason = denialReason,
            SubjectId = subjectId,
            ActorId = actorId,
            FirmId = firmId,
            WorkspaceId = workspaceId,
            Audience = audience,
            RequestedScopes = requestedScopes ?? []
        };

    public static DelegationDecision Forbidden(
        string denialReason,
        string? subjectId = null,
        string? actorId = null,
        string? firmId = null,
        string? workspaceId = null,
        string? audience = null,
        IReadOnlyList<string>? requestedScopes = null) =>
        new()
        {
            Allowed = false,
            FailureKind = DelegationFailureKind.Forbidden,
            Error = "access_denied",
            ErrorDescription = "Delegation is not authorized.",
            DenialReason = denialReason,
            SubjectId = subjectId,
            ActorId = actorId,
            FirmId = firmId,
            WorkspaceId = workspaceId,
            Audience = audience,
            RequestedScopes = requestedScopes ?? []
        };
}

public static class DelegationDenialReasons
{
    public const string MissingAudience = "missing_audience";
    public const string MissingWorkspace = "missing_workspace";
    public const string InvalidScope = "invalid_scope";
    public const string UnknownAudience = "unknown_audience";
    public const string AudienceScopeMismatch = "audience_scope_mismatch";
    public const string MissingSubject = "missing_subject";
    public const string MissingClient = "missing_client";
    public const string MissingFirm = "missing_firm";
    public const string UnknownWorkspace = "unknown_workspace";
    public const string CrossFirm = "cross_firm";
    public const string UserLacksScope = "user_lacks_scope";
    public const string ClientLacksScope = "client_lacks_scope";
}
