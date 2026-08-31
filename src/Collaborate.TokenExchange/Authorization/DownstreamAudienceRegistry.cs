namespace Collaborate.TokenExchange.Authorization;

/// <summary>
/// Server-side allow-list of downstream APIs and the scopes each may receive.
/// Callers cannot mint tokens for arbitrary audiences.
/// </summary>
public interface IDownstreamAudienceRegistry
{
    bool IsRegistered(string audience);

    bool TryGetAllowedScopes(string audience, out IReadOnlySet<string> scopes);
}

public sealed class ConfigurationDownstreamAudienceRegistry : IDownstreamAudienceRegistry
{
    private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> _audiences;

    public ConfigurationDownstreamAudienceRegistry(IReadOnlyDictionary<string, IReadOnlySet<string>> audiences)
    {
        _audiences = audiences;
    }

    public bool IsRegistered(string audience) => _audiences.ContainsKey(audience);

    public bool TryGetAllowedScopes(string audience, out IReadOnlySet<string> scopes) =>
        _audiences.TryGetValue(audience, out scopes!);
}
