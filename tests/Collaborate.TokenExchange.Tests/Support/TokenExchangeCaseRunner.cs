using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Collaborate.TokenExchange.Authentication;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Collaborate.TokenExchange.Tests.Support;

public sealed record IncomingAuthentication
{
    public required string Bearer { get; init; }

    public string? Subject { get; init; }

    public string? ClientId { get; init; }

    public string? FirmId { get; init; }

    public static IncomingAuthentication Missing() => new() { Bearer = "missing" };

    public static IncomingAuthentication Valid(
        string subject = "alice",
        string clientId = "notification-service",
        string firmId = "firm-123") =>
        new()
        {
            Bearer = "valid",
            Subject = subject,
            ClientId = clientId,
            FirmId = firmId
        };

    public static IncomingAuthentication Expired() =>
        Valid() with { Bearer = "expired" };

    public static IncomingAuthentication InvalidSignature() =>
        Valid() with { Bearer = "invalid_signature" };
}

public sealed record ExpectedOutput
{
    public required HttpStatusCode Status { get; init; }

    public bool AccessTokenPresent { get; init; }

    public string? Error { get; init; }

    public string? TokenType { get; init; }

    public string? Scope { get; init; }

    public int? ExpiresIn { get; init; }

    public string? TokenSubject { get; init; }

    public string? TokenActor { get; init; }

    public string? TokenAudience { get; init; }

    public string? TokenWorkspace { get; init; }

    public string? TokenFirm { get; init; }

    public TimeSpan? TokenLifetime { get; init; }

    public IReadOnlyList<string> TokenAudienceMustNotContain { get; init; } = [];

    public IReadOnlyList<string> RejectedAudiences { get; init; } = [];
}

public sealed record ObservedOutput
{
    public required HttpStatusCode Status { get; init; }

    public string? RawBody { get; init; }

    public bool AccessTokenPresent { get; init; }

    public string? Error { get; init; }

    public string? ErrorDescription { get; init; }

    public string? TokenType { get; init; }

    public string? Scope { get; init; }

    public int? ExpiresIn { get; init; }

    public string? TokenSubject { get; init; }

    public string? TokenActor { get; init; }

    public IReadOnlyList<string> TokenAudiences { get; init; } = [];

    public string? TokenWorkspace { get; init; }

    public string? TokenFirm { get; init; }

    public TimeSpan? TokenLifetime { get; init; }

    public IReadOnlyList<string> RejectedAudiences { get; init; } = [];
}

public sealed class TokenExchangeCaseRunner
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private readonly TokenExchangeWebApplicationFactory _factory;

    public TokenExchangeCaseRunner(TokenExchangeWebApplicationFactory factory)
    {
        _factory = factory;
    }

    public async Task<ObservedOutput> Run(
        IncomingAuthentication authentication,
        object request,
        ExpectedOutput expected,
        [CallerMemberName] string testName = "")
    {
        _factory.ServerLog.Drain();
        var started = DateTimeOffset.UtcNow;
        var client = CreateClient(authentication);
        using var response = await client.PostAsJsonAsync("/oauth/token/exchange", request);
        var observed = await Observe(response);
        var serverLog = _factory.ServerLog.Drain();
        var differences = Diff(expected, observed);
        var passed = differences.Count == 0;

        _factory.Log.WriteCase(new TestCaseLogEntry
        {
            Name = testName,
            StartedAt = started,
            Passed = passed,
            Input = FormatInput(authentication, request),
            ExpectedOutput = FormatExpected(expected),
            Output = FormatObserved(observed),
            Differences = differences,
            ServerLog = serverLog
        });

        if (!passed)
        {
            Assert.Fail(string.Join(Environment.NewLine, differences));
        }

        return observed;
    }

    private HttpClient CreateClient(IncomingAuthentication authentication) =>
        authentication.Bearer switch
        {
            "missing" => _factory.CreateClient(),
            "expired" => _factory.CreateAuthenticatedClient(expires: DateTimeOffset.UtcNow.AddHours(-1)),
            "invalid_signature" => _factory.CreateAuthenticatedClient(
                signingKey: TokenExchangeWebApplicationFactory.CreateForeignKey()),
            _ => _factory.CreateAuthenticatedClient(
                subject: authentication.Subject ?? "alice",
                clientId: authentication.ClientId ?? "notification-service",
                firmId: authentication.FirmId ?? "firm-123")
        };

    private async Task<ObservedOutput> Observe(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();
        string? error = null;
        string? errorDescription = null;
        string? tokenType = null;
        string? scope = null;
        int? expiresIn = null;
        string? accessToken = null;

        if (!string.IsNullOrWhiteSpace(raw))
        {
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            if (root.TryGetProperty("error", out var errorEl))
            {
                error = errorEl.GetString();
            }

            if (root.TryGetProperty("error_description", out var descriptionEl))
            {
                errorDescription = descriptionEl.GetString();
            }

            if (root.TryGetProperty("token_type", out var typeEl))
            {
                tokenType = typeEl.GetString();
            }

            if (root.TryGetProperty("scope", out var scopeEl))
            {
                scope = scopeEl.GetString();
            }

            if (root.TryGetProperty("expires_in", out var expiresEl) && expiresEl.TryGetInt32(out var seconds))
            {
                expiresIn = seconds;
            }

            if (root.TryGetProperty("access_token", out var tokenEl))
            {
                accessToken = tokenEl.GetString();
            }
        }

        JwtSecurityToken? jwt = null;
        var rejected = new List<string>();
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            jwt = new JwtSecurityTokenHandler { MapInboundClaims = false }.ReadJwtToken(accessToken);
            foreach (var audience in new[] { "comments-service", "collaborate", "financial-data-api" })
            {
                try
                {
                    new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(
                        accessToken,
                        IssuedTokenValidationParameters(audience, validateLifetime: false),
                        out _);
                }
                catch (SecurityTokenInvalidAudienceException)
                {
                    rejected.Add(audience);
                }
                catch (SecurityTokenException)
                {
                    // Other validation failures are not treated as audience rejection.
                }
            }
        }

        return new ObservedOutput
        {
            Status = response.StatusCode,
            RawBody = RedactAccessToken(raw),
            AccessTokenPresent = !string.IsNullOrWhiteSpace(accessToken),
            Error = error,
            ErrorDescription = errorDescription,
            TokenType = tokenType,
            Scope = scope,
            ExpiresIn = expiresIn,
            TokenSubject = jwt?.Subject,
            TokenActor = jwt?.Claims.FirstOrDefault(c => c.Type == CollaborateClaims.ActorClientId)?.Value,
            TokenAudiences = jwt?.Audiences.ToArray() ?? [],
            TokenWorkspace = jwt?.Claims.FirstOrDefault(c => c.Type == CollaborateClaims.WorkspaceId)?.Value,
            TokenFirm = jwt?.Claims.FirstOrDefault(c => c.Type == CollaborateClaims.FirmId)?.Value,
            TokenLifetime = jwt is null ? null : jwt.ValidTo - jwt.ValidFrom,
            RejectedAudiences = rejected
        };
    }

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

    private static List<string> Diff(ExpectedOutput expected, ObservedOutput actual)
    {
        var diffs = new List<string>();
        Check(diffs, "status", expected.Status, actual.Status);
        Check(diffs, "access_token_present", expected.AccessTokenPresent, actual.AccessTokenPresent);

        if (expected.Error is not null)
        {
            Check(diffs, "error", expected.Error, actual.Error);
        }

        if (expected.TokenType is not null)
        {
            Check(diffs, "token_type", expected.TokenType, actual.TokenType);
        }

        if (expected.Scope is not null)
        {
            Check(diffs, "scope", expected.Scope, actual.Scope);
        }

        if (expected.ExpiresIn is not null)
        {
            Check(diffs, "expires_in", expected.ExpiresIn, actual.ExpiresIn);
        }

        if (expected.TokenSubject is not null)
        {
            Check(diffs, "token.sub", expected.TokenSubject, actual.TokenSubject);
        }

        if (expected.TokenActor is not null)
        {
            Check(diffs, "token.actor_client_id", expected.TokenActor, actual.TokenActor);
        }

        if (expected.TokenAudience is not null)
        {
            var actualAud = actual.TokenAudiences.Count == 1 ? actual.TokenAudiences[0] : string.Join(',', actual.TokenAudiences);
            Check(diffs, "token.aud", expected.TokenAudience, actualAud);
        }

        if (expected.TokenWorkspace is not null)
        {
            Check(diffs, "token.workspace_id", expected.TokenWorkspace, actual.TokenWorkspace);
        }

        if (expected.TokenFirm is not null)
        {
            Check(diffs, "token.firm_id", expected.TokenFirm, actual.TokenFirm);
        }

        if (expected.TokenLifetime is not null)
        {
            Check(diffs, "token.lifetime", expected.TokenLifetime, actual.TokenLifetime);
        }

        foreach (var forbidden in expected.TokenAudienceMustNotContain)
        {
            if (actual.TokenAudiences.Contains(forbidden))
            {
                diffs.Add($"token.aud must not contain {forbidden}");
            }
        }

        foreach (var audience in expected.RejectedAudiences)
        {
            if (!actual.RejectedAudiences.Contains(audience))
            {
                diffs.Add($"issued token was accepted as aud={audience}; expected rejection");
            }
        }

        if (expected.TokenActor is not null && expected.TokenSubject is not null
            && string.Equals(actual.TokenSubject, actual.TokenActor, StringComparison.Ordinal))
        {
            diffs.Add("token.sub must differ from token.actor_client_id");
        }

        return diffs;
    }

    private static void Check<T>(List<string> diffs, string name, T expected, T actual)
    {
        if (!Equals(expected, actual))
        {
            diffs.Add($"{name}: expected {FormatValue(expected)}, output {FormatValue(actual)}");
        }
    }

    private static string FormatInput(IncomingAuthentication authentication, object request)
    {
        var payload = JsonSerializer.Serialize(request, Json);
        return $"""
            authentication:
              bearer: {authentication.Bearer}
              sub: {authentication.Subject ?? "(none)"}
              azp: {authentication.ClientId ?? "(none)"}
              firm_id: {authentication.FirmId ?? "(none)"}
            request:
              POST /oauth/token/exchange
            {payload}
            """;
    }

    private static string FormatExpected(ExpectedOutput expected)
    {
        var lines = new List<string>
        {
            $"status: {(int)expected.Status} {expected.Status}",
            $"access_token: {(expected.AccessTokenPresent ? "present (claims below; raw JWT omitted)" : "(none)")}"
        };

        AddIf(lines, "error", expected.Error);
        AddIf(lines, "token_type", expected.TokenType);
        AddIf(lines, "scope", expected.Scope);
        if (expected.ExpiresIn is not null)
        {
            lines.Add($"expires_in: {expected.ExpiresIn}");
        }

        AddIf(lines, "token.sub", expected.TokenSubject);
        AddIf(lines, "token.actor_client_id", expected.TokenActor);
        AddIf(lines, "token.aud", expected.TokenAudience);
        AddIf(lines, "token.workspace_id", expected.TokenWorkspace);
        AddIf(lines, "token.firm_id", expected.TokenFirm);
        if (expected.TokenLifetime is not null)
        {
            lines.Add($"token.lifetime: {expected.TokenLifetime}");
        }

        if (expected.TokenAudienceMustNotContain.Count > 0)
        {
            lines.Add("token.aud must not contain: " + string.Join(", ", expected.TokenAudienceMustNotContain));
        }

        if (expected.RejectedAudiences.Count > 0)
        {
            lines.Add("token must be rejected for aud: " + string.Join(", ", expected.RejectedAudiences));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatObserved(ObservedOutput actual)
    {
        var lines = new List<string>
        {
            $"status: {(int)actual.Status} {actual.Status}",
            $"access_token: {(actual.AccessTokenPresent ? "present (raw JWT omitted)" : "(none)")}",
            $"body: {actual.RawBody ?? "(empty)"}"
        };

        AddIf(lines, "error", actual.Error);
        AddIf(lines, "error_description", actual.ErrorDescription);
        AddIf(lines, "token_type", actual.TokenType);
        AddIf(lines, "scope", actual.Scope);
        if (actual.ExpiresIn is not null)
        {
            lines.Add($"expires_in: {actual.ExpiresIn}");
        }

        AddIf(lines, "token.sub", actual.TokenSubject);
        AddIf(lines, "token.actor_client_id", actual.TokenActor);
        if (actual.TokenAudiences.Count > 0)
        {
            lines.Add("token.aud: " + string.Join(", ", actual.TokenAudiences));
        }

        AddIf(lines, "token.workspace_id", actual.TokenWorkspace);
        AddIf(lines, "token.firm_id", actual.TokenFirm);
        if (actual.TokenLifetime is not null)
        {
            lines.Add($"token.lifetime: {actual.TokenLifetime}");
        }

        if (actual.RejectedAudiences.Count > 0)
        {
            lines.Add("token rejected for aud: " + string.Join(", ", actual.RejectedAudiences));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static void AddIf(List<string> lines, string name, string? value)
    {
        if (value is not null)
        {
            lines.Add($"{name}: {value}");
        }
    }

    private static string FormatValue<T>(T value) => value is null ? "(null)" : value.ToString() ?? "(null)";

    private static string? RedactAccessToken(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return raw;
        }

        try
        {
            using var document = JsonDocument.Parse(raw);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return raw;
            }

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (property.NameEquals("access_token"))
                    {
                        writer.WriteString(property.Name, "omitted");
                    }
                    else
                    {
                        property.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            return System.Text.Encoding.UTF8.GetString(stream.ToArray());
        }
        catch (JsonException)
        {
            return raw;
        }
    }
}
