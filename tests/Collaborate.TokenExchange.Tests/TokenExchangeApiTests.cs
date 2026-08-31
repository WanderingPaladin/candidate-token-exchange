using System.Net;
using Collaborate.TokenExchange.Tests.Support;
using Xunit;

namespace Collaborate.TokenExchange.Tests;

public sealed class TokenExchangeApiTests : IClassFixture<TokenExchangeWebApplicationFactory>
{
    private readonly TokenExchangeCaseRunner _runner;

    public TokenExchangeApiTests(TokenExchangeWebApplicationFactory factory)
    {
        _runner = new TokenExchangeCaseRunner(factory);
    }

    [Fact]
    public Task Exchange_WithoutBearerToken_Returns401() =>
        _runner.Run(
            IncomingAuthentication.Missing(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.Unauthorized,
                AccessTokenPresent = false
            });

    [Fact]
    public Task Exchange_WithExpiredBearerToken_Returns401() =>
        _runner.Run(
            IncomingAuthentication.Expired(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.Unauthorized,
                AccessTokenPresent = false
            });

    [Fact]
    public Task Exchange_WithInvalidSignature_Returns401() =>
        _runner.Run(
            IncomingAuthentication.InvalidSignature(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.Unauthorized,
                AccessTokenPresent = false
            });

    [Fact]
    public Task Exchange_WhenUserAndClientAndRequestIntersect_ReturnsNarrowToken() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.OK,
                AccessTokenPresent = true,
                TokenType = "Bearer",
                Scope = "documents.read",
                ExpiresIn = 120,
                TokenSubject = "alice",
                TokenActor = "notification-service",
                TokenAudience = "document-service",
                TokenWorkspace = "workspace-123",
                TokenFirm = "firm-123"
            });

    [Fact]
    public Task Exchange_WhenUserLacksRequestedScope_Returns403() =>
        _runner.Run(
            IncomingAuthentication.Valid(subject: "viewer", clientId: "privileged-internal-service"),
            new { audience = "document-service", scope = "documents.write", workspaceId = "workspace-123" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.Forbidden,
                AccessTokenPresent = false,
                Error = "access_denied"
            });

    [Fact]
    public Task Exchange_WhenClientLacksRequestedScope_Returns403() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            new { audience = "document-service", scope = "documents.write", workspaceId = "workspace-123" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.Forbidden,
                AccessTokenPresent = false
            });

    [Fact]
    public Task Exchange_WhenAnyRequestedScopeIsUnauthorized_Returns403() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            new { audience = "document-service", scope = "documents.read documents.write", workspaceId = "workspace-123" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.Forbidden,
                AccessTokenPresent = false
            });

    [Fact]
    public Task Exchange_WithUnregisteredAudience_Returns400() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            new { audience = "evil-api", scope = "documents.read", workspaceId = "workspace-123" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.BadRequest,
                AccessTokenPresent = false,
                Error = "invalid_target"
            });

    [Fact]
    public Task IssuedToken_IsBoundToRequestedAudienceOnly() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.OK,
                AccessTokenPresent = true,
                TokenAudience = "document-service",
                TokenAudienceMustNotContain = ["collaborate", "comments-service"],
                RejectedAudiences = ["comments-service"]
            });

    [Fact]
    public Task Exchange_WhenWorkspaceBelongsToAnotherFirm_Returns403() =>
        _runner.Run(
            IncomingAuthentication.Valid(firmId: "firm-A"),
            new { audience = "document-service", scope = "documents.read", workspaceId = "workspace-b" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.Forbidden,
                AccessTokenPresent = false
            });

    [Fact]
    public Task IssuedToken_ExpiresWithinConfiguredLifetime() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.OK,
                AccessTokenPresent = true,
                ExpiresIn = 120,
                TokenLifetime = TimeSpan.FromMinutes(2)
            });

    [Fact]
    public Task IssuedToken_DistinguishesSubjectFromActingClient() =>
        _runner.Run(
            IncomingAuthentication.Valid(subject: "alice", clientId: "notification-service"),
            DocumentRead(),
            new ExpectedOutput
            {
                Status = HttpStatusCode.OK,
                AccessTokenPresent = true,
                TokenSubject = "alice",
                TokenActor = "notification-service",
                TokenAudience = "document-service"
            });

    [Fact]
    public Task Exchange_IgnoresUserIdInRequestBody_SubjectComesFromToken() =>
        _runner.Run(
            IncomingAuthentication.Valid(subject: "alice"),
            new
            {
                audience = "document-service",
                scope = "documents.read",
                workspaceId = "workspace-123",
                userId = "mallory"
            },
            new ExpectedOutput
            {
                Status = HttpStatusCode.OK,
                AccessTokenPresent = true,
                TokenSubject = "alice"
            });

    [Fact]
    public Task Exchange_WithMalformedScope_Returns400() =>
        _runner.Run(
            IncomingAuthentication.Valid(),
            new { audience = "document-service", scope = "documents.delete", workspaceId = "workspace-123" },
            new ExpectedOutput
            {
                Status = HttpStatusCode.BadRequest,
                AccessTokenPresent = false,
                Error = "invalid_scope"
            });

    private static object DocumentRead() => new
    {
        audience = "document-service",
        scope = "documents.read",
        workspaceId = "workspace-123"
    };
}
