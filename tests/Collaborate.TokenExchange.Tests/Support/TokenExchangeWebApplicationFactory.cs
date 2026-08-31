using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Collaborate.TokenExchange.Authentication;
using Collaborate.TokenExchange.Configuration;
using Collaborate.TokenExchange.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Tests.Support;

public sealed class TokenExchangeWebApplicationFactory : WebApplicationFactory<Program>
{
    public FakeTimeProvider Time { get; } = new(new DateTimeOffset(2026, 8, 31, 12, 0, 0, TimeSpan.Zero));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);
        });
    }

    public HttpClient CreateAuthenticatedClient(
        string subject = "alice",
        string clientId = "notification-service",
        string firmId = "firm-123",
        DateTimeOffset? expires = null,
        SecurityKey? signingKey = null)
    {
        var client = CreateClient();
        var token = IssueIncomingToken(subject, clientId, firmId, expires, signingKey);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public string IssueIncomingToken(
        string subject,
        string clientId,
        string firmId,
        DateTimeOffset? expires = null,
        SecurityKey? signingKey = null)
    {
        var options = Services.GetRequiredService<IOptions<TokenExchangeOptions>>().Value;
        var key = signingKey ?? Services.GetRequiredService<ISigningCredentialProvider>().GetValidationKey();
        var now = DateTimeOffset.UtcNow;
        var lifetimeEnd = expires ?? now.AddMinutes(10);
        var issuedAt = expires.HasValue ? expires.Value.AddMinutes(-10) : now;

        var claims = new List<Claim>
        {
            new(CollaborateClaims.Subject, subject),
            new(CollaborateClaims.AuthorizedParty, clientId),
            new(CollaborateClaims.FirmId, firmId)
        };

        var payload = new JwtPayload(
            issuer: options.IncomingIssuer,
            audience: options.IncomingAudience,
            claims: claims,
            notBefore: issuedAt.UtcDateTime,
            expires: lifetimeEnd.UtcDateTime,
            issuedAt: issuedAt.UtcDateTime);

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(new JwtHeader(credentials), payload);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static SymmetricSecurityKey CreateForeignKey() =>
        new(Encoding.UTF8.GetBytes("EVIL-SIGNING-KEY-NOT-THE-SERVER-KEY!!"));

    public TokenExchangeOptions Options =>
        Services.GetRequiredService<IOptions<TokenExchangeOptions>>().Value;

    public SecurityKey ValidationKey =>
        Services.GetRequiredService<ISigningCredentialProvider>().GetValidationKey();
}
