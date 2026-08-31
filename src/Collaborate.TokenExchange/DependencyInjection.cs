using Collaborate.TokenExchange.Authentication;
using Collaborate.TokenExchange.Authorization;
using Collaborate.TokenExchange.Configuration;
using Collaborate.TokenExchange.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange;

public static class DependencyInjection
{
    public static IServiceCollection AddCollaborateTokenExchange(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services
            .AddOptions<TokenExchangeOptions>()
            .Bind(configuration.GetSection(TokenExchangeOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddOptions<ClientAuthorizationOptions>()
            .Configure(options =>
            {
                var bound = configuration
                    .GetSection(ClientAuthorizationOptions.SectionName)
                    .Get<Dictionary<string, Dictionary<string, string[]>>>();

                if (bound is not null)
                {
                    options.Registrations = new Dictionary<string, Dictionary<string, string[]>>(
                        bound,
                        StringComparer.Ordinal);
                }
            });

        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ISigningCredentialProvider, DevelopmentSigningCredentialProvider>();
        services.AddSingleton<ICallingClientResolver, CallingClientResolver>();
        services.AddSingleton<IPermissionService, InMemoryPermissionService>();
        services.AddSingleton<IClientAuthorizationService, ConfigurationClientAuthorizationService>();
        services.AddSingleton<IDownstreamAudienceRegistry>(_ =>
            new ConfigurationDownstreamAudienceRegistry(ReadDownstreamApis(configuration)));
        services.AddSingleton<ITokenIssuer, JwtTokenIssuer>();
        services.AddScoped<IDelegationAuthorizationService, DelegationAuthorizationService>();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        services
            .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<ISigningCredentialProvider, Microsoft.Extensions.Options.IOptions<TokenExchangeOptions>>(
                (jwt, signing, tokenOptions) =>
                {
                    var options = tokenOptions.Value;
                    jwt.MapInboundClaims = false;
                    jwt.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = options.IncomingIssuer,
                        ValidateAudience = true,
                        ValidAudience = options.IncomingAudience,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = signing.GetValidationKey(),
                        ClockSkew = TimeSpan.FromSeconds(30),
                        NameClaimType = CollaborateClaims.Subject,
                        RequireSignedTokens = true,
                        RequireExpirationTime = true
                    };
                });

        services.AddAuthorization();
        return services;
    }

    private static IReadOnlyDictionary<string, IReadOnlySet<string>> ReadDownstreamApis(IConfiguration configuration)
    {
        var bound = configuration.GetSection("DownstreamApis").Get<Dictionary<string, string[]>>()
                    ?? new Dictionary<string, string[]>();

        var result = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        foreach (var (audience, scopes) in bound)
        {
            result[audience] = new HashSet<string>(scopes, StringComparer.Ordinal);
        }

        return result;
    }
}
