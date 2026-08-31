using System.ComponentModel.DataAnnotations;

namespace Collaborate.TokenExchange.Configuration;

public sealed class TokenExchangeOptions
{
    public const string SectionName = "TokenExchange";

    [Required]
    public string IncomingIssuer { get; set; } = string.Empty;

    [Required]
    public string IncomingAudience { get; set; } = string.Empty;

    [Required]
    public string OutgoingIssuer { get; set; } = string.Empty;

    /// <summary>
    /// Delegated tokens are intentionally short-lived. Production should keep
    /// this small (minutes, not hours) and rely on a new exchange after expiry.
    /// </summary>
    [Range(1, 10)]
    public int DelegatedTokenLifetimeMinutes { get; set; } = 2;

    /// <summary>
    /// Local/test HMAC material only. Never a production secret.
    /// Production must replace <see cref="Tokens.ISigningCredentialProvider"/>.
    /// </summary>
    [Required]
    public string DevelopmentSigningKey { get; set; } = string.Empty;
}
