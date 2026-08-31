namespace Collaborate.TokenExchange.Models;

/// <summary>
/// Simplified JSON token-exchange request. This is not the RFC 8693 form
/// body; it is a small Collaborate-specific contract for the assessment.
/// </summary>
public sealed record TokenExchangeRequest
{
    public string? Audience { get; init; }

    public string? Scope { get; init; }

    public string? WorkspaceId { get; init; }
}
