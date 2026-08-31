using Microsoft.Extensions.Options;

namespace Collaborate.TokenExchange.Authorization;

/// <summary>
/// Maximum authority a registered calling client/service may request for a
/// downstream audience. This is the application's own grant, not the user's.
/// </summary>
public interface IClientAuthorizationService
{
    Task<IReadOnlySet<string>> GetAllowedScopesAsync(
        string clientId,
        string audience,
        CancellationToken cancellationToken);
}

public sealed class ConfigurationClientAuthorizationService : IClientAuthorizationService
{
    private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlySet<string>>> _registrations;

    public ConfigurationClientAuthorizationService(IOptions<ClientAuthorizationOptions> options)
    {
        _registrations = options.Value.ToLookup();
    }

    public Task<IReadOnlySet<string>> GetAllowedScopesAsync(
        string clientId,
        string audience,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_registrations.TryGetValue(clientId, out var audiences)
            && audiences.TryGetValue(audience, out var scopes))
        {
            return Task.FromResult(scopes);
        }

        return Task.FromResult<IReadOnlySet<string>>(new HashSet<string>(StringComparer.Ordinal));
    }
}

public sealed class ClientAuthorizationOptions
{
    public const string SectionName = "Clients";

    public Dictionary<string, Dictionary<string, string[]>> Registrations { get; set; } =
        new(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlySet<string>>> ToLookup()
    {
        var result = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlySet<string>>>(StringComparer.Ordinal);

        foreach (var (clientId, audiences) in Registrations)
        {
            var audienceMap = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
            foreach (var (audience, scopes) in audiences)
            {
                audienceMap[audience] = new HashSet<string>(scopes, StringComparer.Ordinal);
            }

            result[clientId] = audienceMap;
        }

        return result;
    }
}
