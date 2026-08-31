using System.Text;
using Collaborate.TokenExchange.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Tokens;

/// <summary>
/// Supplies signing/validation keys. Production should back this with the
/// platform key-management system (for example AWS KMS / HSM) and rotate
/// keys independently of application deployments. This assessment uses a
/// development HMAC key so tests can run without an identity provider.
/// </summary>
public interface ISigningCredentialProvider
{
    SigningCredentials GetSigningCredentials();

    SecurityKey GetValidationKey();
}

public sealed class DevelopmentSigningCredentialProvider : ISigningCredentialProvider
{
    public const string DevelopmentKeyId = "dev-hs256";

    private readonly SymmetricSecurityKey _key;
    private readonly SigningCredentials _credentials;

    public DevelopmentSigningCredentialProvider(
        IOptions<TokenExchangeOptions> options,
        IHostEnvironment environment)
    {
        if (environment.IsProduction())
        {
            throw new InvalidOperationException(
                "The development signing credential provider must not be used in Production. " +
                "Replace ISigningCredentialProvider with managed key material.");
        }

        _key = CreateDevelopmentKey(options.Value.DevelopmentSigningKey);
        _credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
    }

    public SigningCredentials GetSigningCredentials() => _credentials;

    public SecurityKey GetValidationKey() => _key;

    internal static SymmetricSecurityKey CreateDevelopmentKey(string configuredKey)
    {
        var bytes = Encoding.UTF8.GetBytes(configuredKey);
        if (bytes.Length < 32)
        {
            throw new InvalidOperationException("Development signing key must be at least 256 bits.");
        }

        return new SymmetricSecurityKey(bytes) { KeyId = DevelopmentKeyId };
    }
}
