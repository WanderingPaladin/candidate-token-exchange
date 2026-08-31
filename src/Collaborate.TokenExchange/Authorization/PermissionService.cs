namespace Collaborate.TokenExchange.Authorization;

/// <summary>
/// Current user authorization in a workspace. Production would compose
/// firm policy + workspace role + resource overrides, typically served
/// from a Redis-backed cache invalidated on permission-change events.
/// </summary>
public interface IPermissionService
{
    Task<PermissionEvaluation> EvaluateAsync(
        string subjectId,
        string firmId,
        string workspaceId,
        CancellationToken cancellationToken);
}

public enum PermissionStatus
{
    Granted,
    UnknownWorkspace,
    CrossFirm,
    None
}

public sealed record PermissionEvaluation(
    PermissionStatus Status,
    IReadOnlySet<string> Permissions);

/// <summary>
/// Assessment stub. Encodes demo users, workspace-to-firm ownership, and
/// current grants so tenant isolation and confused-deputy rules are testable
/// without a permission database.
/// </summary>
public sealed class InMemoryPermissionService : IPermissionService
{
    private static readonly Dictionary<string, string> WorkspaceToFirm = new(StringComparer.Ordinal)
    {
        ["workspace-123"] = "firm-123",
        ["workspace-a"] = "firm-A",
        ["workspace-b"] = "firm-B"
    };

    private static readonly Dictionary<(string Subject, string Workspace), HashSet<string>> Grants =
        new()
        {
            [("alice", "workspace-123")] =
            [
                "documents.read",
                "documents.write",
                "comments.read",
                "comments.write"
            ],
            [("alice", "workspace-a")] = ["documents.read"],
            [("viewer", "workspace-123")] = ["documents.read"]
        };

    public Task<PermissionEvaluation> EvaluateAsync(
        string subjectId,
        string firmId,
        string workspaceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!WorkspaceToFirm.TryGetValue(workspaceId, out var ownerFirm))
        {
            return Task.FromResult(new PermissionEvaluation(PermissionStatus.UnknownWorkspace, FrozenEmpty()));
        }

        // Firm identity comes from the validated token, never the request body.
        if (!string.Equals(ownerFirm, firmId, StringComparison.Ordinal))
        {
            return Task.FromResult(new PermissionEvaluation(PermissionStatus.CrossFirm, FrozenEmpty()));
        }

        if (!Grants.TryGetValue((subjectId, workspaceId), out var permissions) || permissions.Count == 0)
        {
            return Task.FromResult(new PermissionEvaluation(PermissionStatus.None, FrozenEmpty()));
        }

        return Task.FromResult(new PermissionEvaluation(
            PermissionStatus.Granted,
            new HashSet<string>(permissions, StringComparer.Ordinal)));
    }

    private static IReadOnlySet<string> FrozenEmpty() => new HashSet<string>(StringComparer.Ordinal);
}
