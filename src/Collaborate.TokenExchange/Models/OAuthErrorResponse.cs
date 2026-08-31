using System.Text.Json.Serialization;

namespace Collaborate.TokenExchange.Models;

public sealed record OAuthErrorResponse
{
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    [JsonPropertyName("error_description")]
    public required string ErrorDescription { get; init; }
}
