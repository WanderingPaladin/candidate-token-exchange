using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Collaborate.TokenExchange.Authentication;
using Collaborate.TokenExchange.Models;
using Collaborate.TokenExchange.Tests.Support;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Collaborate.TokenExchange.Tests;

public sealed class TokenExchangeApiTests : IClassFixture<TokenExchangeWebApplicationFactory>
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    private readonly TokenExchangeWebApplicationFactory _factory;

    public TokenExchangeApiTests(TokenExchangeWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Exchange_WithoutBearerToken_Returns401()
    {
        var client = _factory.CreateClient();

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task Exchange_WithExpiredBearerToken_Returns401()
    {
        var client = _factory.CreateAuthenticatedClient(expires: DateTimeOffset.UtcNow.AddHours(-1));

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task Exchange_WithInvalidSignature_Returns401()
    {
        var client = _factory.CreateAuthenticatedClient(signingKey: TokenExchangeWebApplicationFactory.CreateForeignKey());

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task Exchange_WhenUserAndClientAndRequestIntersect_ReturnsNarrowToken()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(Json);
        Assert.NotNull(body);
        Assert.Equal("Bearer", body.TokenType);
        Assert.Equal("documents.read", body.Scope);
        Assert.Equal(120, body.ExpiresIn);
        Assert.False(string.IsNullOrWhiteSpace(body.AccessToken));

        var jwt = ReadAndValidateIssuedToken(body.AccessToken, expectedAudience: "document-service");
        Assert.Equal("alice", jwt.Subject);
        Assert.Equal("notification-service", Claim(jwt, CollaborateClaims.ActorClientId));
        Assert.Equal(["document-service"], jwt.Audiences);
        Assert.Equal("documents.read", Claim(jwt, CollaborateClaims.Scope));
        Assert.Equal("workspace-123", Claim(jwt, CollaborateClaims.WorkspaceId));
        Assert.Equal("firm-123", Claim(jwt, CollaborateClaims.FirmId));
    }

    [Fact]
    public async Task Exchange_WhenUserLacksRequestedScope_Returns403()
    {
        // viewer has documents.read only. privileged-internal-service may request
        // documents.write. The service's extra authority must not elevate the user.
        var client = _factory.CreateAuthenticatedClient(
            subject: "viewer",
            clientId: "privileged-internal-service");

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.write",
            workspaceId = "workspace-123"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
        Assert.Equal("access_denied", (await ReadErrorAsync(response)).Error);
    }

    [Fact]
    public async Task Exchange_WhenClientLacksRequestedScope_Returns403()
    {
        // alice has documents.write; notification-service does not.
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.write",
            workspaceId = "workspace-123"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task Exchange_WhenAnyRequestedScopeIsUnauthorized_Returns403()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.read documents.write",
            workspaceId = "workspace-123"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task Exchange_WithUnregisteredAudience_Returns400()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, new
        {
            audience = "evil-api",
            scope = "documents.read",
            workspaceId = "workspace-123"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
        Assert.Equal("invalid_target", (await ReadErrorAsync(response)).Error);
    }

    [Fact]
    public async Task IssuedToken_IsBoundToRequestedAudienceOnly()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());
        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(Json);
        Assert.NotNull(body);

        var jwt = ReadAndValidateIssuedToken(body.AccessToken, expectedAudience: "document-service");
        Assert.Equal(["document-service"], jwt.Audiences);
        Assert.DoesNotContain("collaborate", jwt.Audiences);
        Assert.DoesNotContain("comments-service", jwt.Audiences);

        var handler = CreateIssuedTokenHandler();
        Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
            handler.ValidateToken(
                body.AccessToken,
                IssuedTokenValidationParameters(validAudience: "comments-service", validateLifetime: false),
                out _));
    }

    [Fact]
    public async Task Exchange_WhenWorkspaceBelongsToAnotherFirm_Returns403()
    {
        var client = _factory.CreateAuthenticatedClient(firmId: "firm-A");

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.read",
            workspaceId = "workspace-b"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    [Fact]
    public async Task IssuedToken_ExpiresWithinConfiguredLifetime()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());
        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(Json);
        Assert.NotNull(body);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(body.AccessToken);
        Assert.Equal(TimeSpan.FromMinutes(2), jwt.ValidTo - jwt.ValidFrom);
        Assert.Equal(120, body.ExpiresIn);
        Assert.Equal(_factory.Time.GetUtcNow().UtcDateTime, jwt.ValidFrom, TimeSpan.FromSeconds(1));
        Assert.Equal(_factory.Time.GetUtcNow().AddMinutes(2).UtcDateTime, jwt.ValidTo, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task IssuedToken_DistinguishesSubjectFromActingClient()
    {
        var client = _factory.CreateAuthenticatedClient(
            subject: "alice",
            clientId: "notification-service");

        var response = await ExchangeAsync(client, ValidDocumentReadRequest());
        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(Json);
        Assert.NotNull(body);

        var jwt = ReadAndValidateIssuedToken(body.AccessToken, expectedAudience: "document-service");
        Assert.Equal("alice", jwt.Subject);
        Assert.Equal("notification-service", Claim(jwt, CollaborateClaims.ActorClientId));
        Assert.NotEqual(jwt.Subject, Claim(jwt, CollaborateClaims.ActorClientId));
    }

    [Fact]
    public async Task Exchange_IgnoresUserIdInRequestBody_SubjectComesFromToken()
    {
        var client = _factory.CreateAuthenticatedClient(subject: "alice");

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.read",
            workspaceId = "workspace-123",
            userId = "mallory"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(Json);
        Assert.NotNull(body);
        Assert.Equal("alice", new JwtSecurityTokenHandler().ReadJwtToken(body.AccessToken).Subject);
    }

    [Fact]
    public async Task Exchange_WithMalformedScope_Returns400()
    {
        var client = _factory.CreateAuthenticatedClient();

        var response = await ExchangeAsync(client, new
        {
            audience = "document-service",
            scope = "documents.delete",
            workspaceId = "workspace-123"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_scope", (await ReadErrorAsync(response)).Error);
        Assert.Null(await ReadAccessTokenAsync(response));
    }

    private static object ValidDocumentReadRequest() => new
    {
        audience = "document-service",
        scope = "documents.read",
        workspaceId = "workspace-123"
    };

    private static Task<HttpResponseMessage> ExchangeAsync(HttpClient client, object body) =>
        client.PostAsJsonAsync("/oauth/token/exchange", body);

    private static async Task<string?> ReadAccessTokenAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty("access_token", out var token)
            ? token.GetString()
            : null;
    }

    private static async Task<OAuthErrorResponse> ReadErrorAsync(HttpResponseMessage response)
    {
        var error = await response.Content.ReadFromJsonAsync<OAuthErrorResponse>(Json);
        Assert.NotNull(error);
        return error;
    }

    private JwtSecurityToken ReadAndValidateIssuedToken(string accessToken, string expectedAudience)
    {
        var handler = CreateIssuedTokenHandler();
        handler.ValidateToken(
            accessToken,
            IssuedTokenValidationParameters(expectedAudience, validateLifetime: false),
            out var validated);

        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal(expectedAudience, jwt.Audiences.Single());
        return jwt;
    }

    private static JwtSecurityTokenHandler CreateIssuedTokenHandler() =>
        new() { MapInboundClaims = false };

    private TokenValidationParameters IssuedTokenValidationParameters(string validAudience, bool validateLifetime) =>
        new()
        {
            ValidateIssuer = true,
            ValidIssuer = _factory.Options.OutgoingIssuer,
            ValidateAudience = true,
            ValidAudience = validAudience,
            ValidateLifetime = validateLifetime,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _factory.ValidationKey,
            ClockSkew = TimeSpan.Zero,
            RequireSignedTokens = true
        };

    private static string Claim(JwtSecurityToken jwt, string type) =>
        jwt.Claims.Single(claim => claim.Type == type).Value;
}
