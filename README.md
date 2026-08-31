# Collaborate token exchange (Part 2, Option C)

Targeted ASP.NET Core demonstration of **on-behalf-of (OBO) token exchange** for the Caseware Collaborate senior take-home.

This is **not** an authorization server, identity provider, SAML implementation, or production key-management platform. It is a small, explainable slice of the authorization layer described in Part 1.

The contract is **conceptually aligned** with OAuth 2.0 Token Exchange (RFC 8693). It is **not** a full RFC 8693 implementation: the request is JSON rather than `application/x-www-form-urlencoded`, and there is no `grant_type` / `subject_token` form contract.

## What this implementation demonstrates

- Validated incoming bearer tokens via ASP.NET Core `AddJwtBearer` (signature, issuer, audience, lifetime).
- An authenticated `POST /oauth/token/exchange` endpoint.
- On-behalf-of delegation: a calling service receives a **new, narrower** downstream token.
- Scope narrowing by intersection, fail-closed (no silent partial grants).
- Server-side downstream audience allow-listing.
- User + acting-client attribution on the issued token.
- Same-firm / workspace isolation.
- Short-lived issued tokens (2 minutes by default).
- Structured audit logs that never include bearer tokens or keys.

## Request flow

```
Alice (validated JWT: sub, azp, firm_id, aud=collaborate)
        |
        v
POST /oauth/token/exchange
Authorization: Bearer <incoming access token>
        |
        v
ASP.NET Core JwtBearer authentication
        |  401 if missing / malformed / bad signature / expired / wrong iss/aud
        v
ClaimsPrincipal  (subject, acting client, firm — never from the JSON body)
        |
        v
DelegationAuthorizationService
        |  400 invalid request / unknown audience / bad scope
        |  403 authenticated but not allowed to delegate
        v
requested ⊆ user authority
        ∩ client authority
        ∩ audience catalog
        ∩ same-firm workspace
        |
        v
JwtTokenIssuer  (Microsoft.IdentityModel only)
        |
        v
{ access_token, token_type: Bearer, expires_in: 120, scope }
```

Example success:

```http
POST /oauth/token/exchange
Authorization: Bearer <alice + notification-service token>
Content-Type: application/json

{
  "audience": "document-service",
  "scope": "documents.read",
  "workspaceId": "workspace-123"
}
```

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 120,
  "scope": "documents.read"
}
```

The issued JWT carries a deliberate claim set:

| Claim | Meaning |
| --- | --- |
| `sub` | Delegated user (from the validated incoming `sub`) |
| `actor_client_id` | Calling service (from incoming `azp` / `client_id`) |
| `aud` | Requested downstream API only (e.g. `document-service`) |
| `scope` | Approved scopes only |
| `firm_id` | Tenant from the incoming token |
| `workspace_id` | Workspace that was authorized |
| `iss` / `iat` / `exp` / `nbf` / `jti` | Standard JWT metadata |

`actor_client_id` is used instead of RFC 8693's nested `act.sub` object so attribution stays obvious with the standard JWT library. A production token service could emit the structured `act` claim without changing the authorization rule.

## Security invariants

1. **No authentication → no exchange** (401 from the framework).
2. **Subject is never taken from the request body.** Extra fields such as `userId` are ignored.
3. **Acting client is never taken from the request body.** It comes from `azp` or `client_id` on the validated principal.
4. **Firm is never taken from the request body.** Cross-firm workspace requests are denied (403).
5. **Unknown audiences are rejected** (400 `invalid_target`). Tokens cannot be minted for `evil-api`.
6. **Unrecognized / duplicate / empty scopes are rejected** (400 `invalid_scope`).
7. **Delegated scope = requested ∩ user ∩ client ∩ audience.** If any requested scope is outside that set, the entire request is denied (403). This slice does **not** silently grant the allowed subset.
8. **Confused-deputy defense:** a privileged service cannot use Alice's identity to exercise authority Alice does not have, and Alice's broader grants cannot expand a narrowly registered client.
9. **Issued tokens are audience-bound** (`aud` is the downstream API, not `collaborate`).
10. **Issued tokens are short-lived** (configurable, default 2 minutes). No refresh tokens.
11. **Incoming tokens are not forwarded.** Downstream services receive a newly constructed claim set.
12. **Logs never include** incoming bearer tokens, issued access tokens, or signing keys.

### HTTP status contract

| Status | When |
| --- | --- |
| **401** | Authentication failed: missing, malformed, unsigned, bad signature, expired, wrong issuer/audience. Produced by JwtBearer middleware. |
| **400** | The exchange request itself is invalid: missing audience/workspace/scope, unrecognized or duplicate scopes, or an audience that is not registered. OAuth-style `{ "error", "error_description" }`. Unknown audience is **400** (`invalid_target`) because it is not a registered resource, not an authorization miss on a known one. |
| **403** | The caller is authenticated, but delegation is not authorized: user or client lacks a requested scope, workspace is unknown, or the workspace belongs to another firm. Public description is generic (`access_denied`) so responses do not leak tenant or grant details. |

### Why user authority is not read from incoming token scopes

The incoming token proves **who** is calling (user, client, firm). Current **what** they may do is evaluated by `IPermissionService` for the requested workspace.

That matches Collaborate's model: workspace roles, resource overrides, and firm policy live in Collaborate's store and can change while an access token is still valid. Using live permissions (rather than copying scopes from the incoming JWT) is also the hook a production system would use for fast revocation.

## What is deliberately stubbed

| Component | Assessment stand-in | Production replacement |
| --- | --- | --- |
| Incoming token issuer | Tests/local JWTs signed with a development HMAC key | Caseware IdP (OIDC discovery + JWKS) |
| User permissions | `InMemoryPermissionService` (alice / viewer demo grants + workspace-to-firm map) | Collaborate permission database + Redis cache + change events |
| Client registration | `Clients` section in `appsettings.json` | Real registered application/service identities |
| Downstream audiences | `DownstreamApis` section in `appsettings.json` | Controlled API registry |
| Signing keys | `DevelopmentSigningCredentialProvider` (process HMAC, refused in Production) | AWS KMS / HSM-backed keys, rotation, JWKS for downstream validators |
| Workload authentication | Client id taken from the user access token's `azp` / `client_id` | Private-key JWT, mTLS, or the existing service-identity system **in addition to** the user token |

Demo data used by tests:

- **alice** / `firm-123` / `workspace-123`: `documents.read`, `documents.write`, `comments.read`, `comments.write`
- **viewer** / `firm-123` / `workspace-123`: `documents.read`
- **workspace-b** belongs to **firm-B** (used to deny cross-firm exchange)
- **notification-service** may request only `documents.read` from `document-service`
- **privileged-internal-service** may request `documents.read` and `documents.write` from `document-service` — still cannot exceed the user's grants

## Security decisions worth reviewing in person

These are the decisions I would walk through in a design review. They are also the places AI output must not be trusted without a human check.

- **Token validation** is entirely ASP.NET Core JwtBearer + `Microsoft.IdentityModel.Tokens`. There is no manual JWT split, Base64 decode, or custom signature code.
- **`MapInboundClaims = false`** so `sub`, `azp`, and `firm_id` keep their JWT names.
- **Incoming vs outgoing tokens are different instruments:** incoming `iss` is the IdP and `aud` is `collaborate`. Outgoing `iss` is this service and `aud` is the downstream API. A document-service token cannot be replayed against this exchange endpoint.
- **Scope comparison is exact and case-sensitive** after trim/split. OAuth scopes are case-sensitive; we do not fold case.
- **Fail closed on partial scope requests.** `documents.read documents.write` is denied if either side cannot grant write. Partial grant would be a product decision; this assessment prefers the obvious denial.
- **Tenant isolation** compares the token's `firm_id` to the stub workspace owner. The request cannot override firm.
- **Development HMAC key** is labeled and is not production material. `DevelopmentSigningCredentialProvider` throws if `ASPNETCORE_ENVIRONMENT=Production`.

## Project tree

```
├── README.md
├── Collaborate.TokenExchange.sln
├── src/Collaborate.TokenExchange/
│   ├── Program.cs
│   ├── DependencyInjection.cs
│   ├── appsettings.json
│   ├── Authentication/
│   │   ├── CallingClientResolver.cs
│   │   └── CollaborateClaims.cs
│   ├── Authorization/
│   │   ├── DelegationAuthorizationService.cs
│   │   ├── DelegationDecision.cs
│   │   ├── PermissionService.cs
│   │   ├── ClientAuthorizationService.cs
│   │   ├── DownstreamAudienceRegistry.cs
│   │   └── ScopeParser.cs
│   ├── Controllers/TokenExchangeController.cs
│   ├── Models/
│   ├── Configuration/
│   └── Tokens/
│       ├── JwtTokenIssuer.cs
│       └── SigningCredentialProvider.cs
└── tests/Collaborate.TokenExchange.Tests/
    ├── TokenExchangeApiTests.cs
    └── Support/TokenExchangeWebApplicationFactory.cs
```

## Running locally

Requires the .NET 8 SDK.

```bash
dotnet test Collaborate.TokenExchange.sln
dotnet run --project src/Collaborate.TokenExchange
```

There is no login UI and no public token minting endpoint. Incoming tokens for manual calls must be signed with the development key and use:

- `iss`: `https://idp.caseware.example`
- `aud`: `collaborate`
- `sub`, `azp`, `firm_id`

## Production changes still required

- Validate incoming tokens against the real IdP JWKS (`Authority` / metadata address), not a local HMAC key.
- Persist and cache permissions; subscribe to role/override/revocation events (target: effect within seconds, including long-lived collaborative sessions).
- Authenticate calling workloads independently of the user access token.
- Store and rotate signing keys in KMS/HSM; publish JWKS for Document Service / Comments Service / Financial Data API.
- Require a dedicated incoming scope or client grant before exchange is allowed (this slice only requires an authenticated caller).
- Add distributed tracing/metrics for allow/deny rates, without logging secrets.
- Decide whether a future product need justifies RFC 8693's formal form post and nested `act` claim.

## AI usage (for the follow-up review)

AI (Cursor) was used to scaffold the .NET project, wire ASP.NET Core JWT bearer authentication, and draft tests around the stated invariants.

I treated the following as **human-owned**, not "trust the generated code":

- The authorization intersection and fail-closed rule
- Subject / actor / firm sourced only from `ClaimsPrincipal`
- Audience allow-listing
- Tenant isolation
- Claim set of the issued token
- What is logged vs never logged
- Status code contract (401 / 400 / 403)

I would tell other engineers the same thing: AI is useful for framework boilerplate and test scaffolding on this system. It should not be the source of truth for token validation parameters, scope comparison, or tenant checks. Those rules are short; write them so you can explain them without the tool.
