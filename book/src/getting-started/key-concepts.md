# Key Concepts

This page defines the core terminology used throughout the Barycenter documentation. If you are already familiar with OAuth 2.0, OIDC, and WebAuthn, you can skip ahead to the [installation guide](./installation.md).

## OpenID Connect (OIDC)

OpenID Connect is an identity layer built on top of OAuth 2.0. While OAuth 2.0 handles *authorization* (granting access to resources), OIDC adds *authentication* (verifying who a user is). OIDC introduces the concept of an ID Token -- a signed JWT that contains claims about the authenticated user. Barycenter implements OIDC Core 1.0 as the identity provider (also called the OpenID Provider or OP).

## OAuth 2.0

OAuth 2.0 is the industry-standard authorization framework that allows third-party applications to obtain limited access to a user's resources without exposing their credentials. It defines grant types (ways to obtain tokens), scopes (permissions), and token types. Barycenter uses OAuth 2.0 as the foundation for its token issuance and access control.

## Authorization Code Flow

The Authorization Code flow is the most secure OAuth 2.0 grant type for server-side and native applications. The flow works in two steps: first, the user authenticates and the authorization server returns a short-lived authorization code to the client via a redirect; second, the client exchanges that code for tokens by calling the token endpoint directly. This two-step process keeps tokens out of the browser's URL bar and history. Barycenter uses this as its primary flow and requires PKCE for all authorization code requests.

## PKCE (Proof Key for Code Exchange)

PKCE (pronounced "pixy") is an extension to the Authorization Code flow that prevents authorization code interception attacks. The client generates a random `code_verifier`, derives a `code_challenge` from it using SHA-256, and sends the challenge with the authorization request. When exchanging the code for tokens, the client sends the original verifier, and the server verifies it matches the stored challenge. Barycenter only supports the S256 challenge method -- the plain method is rejected.

## WebAuthn / Passkeys

WebAuthn (Web Authentication) is a W3C standard that enables passwordless authentication using public-key cryptography. A *passkey* is a WebAuthn credential that can be either hardware-bound (e.g., a YubiKey) or cloud-synced (e.g., iCloud Keychain, Google Password Manager). Barycenter supports passkeys for both single-factor authentication (replacing passwords entirely) and as a second factor after password login.

## AMR (Authentication Method References)

AMR is a claim in the ID Token that indicates which authentication methods were used during the login session. Barycenter tracks the following AMR values:

- `pwd` -- password authentication
- `hwk` -- hardware-bound passkey (e.g., YubiKey, security key)
- `swk` -- software/cloud-synced passkey (e.g., iCloud Keychain, password manager)

Multiple values indicate multi-factor authentication. For example, `["pwd", "hwk"]` means the user authenticated with both a password and a hardware security key.

## ACR (Authentication Context Class Reference)

ACR is a claim in the ID Token that indicates the overall assurance level of the authentication. Barycenter uses two levels:

- `aal1` -- single-factor authentication (password only, or passkey only)
- `aal2` -- two-factor authentication (password plus passkey, or equivalent)

Relying parties can request a minimum ACR level by including the `acr_values` parameter in the authorization request.

## JWT (JSON Web Token)

A JWT is a compact, URL-safe token format consisting of three Base64url-encoded parts separated by dots: a header, a payload (claims), and a signature. Barycenter issues ID Tokens as signed JWTs using RS256 (RSA with SHA-256). The header includes a `kid` (Key ID) that maps to the corresponding public key in the JWKS endpoint.

## ID Token

The ID Token is a JWT issued by Barycenter that contains claims about the authentication event and the authenticated user. Standard claims include `iss` (issuer), `sub` (subject), `aud` (audience), `exp` (expiration), and `iat` (issued at). Barycenter also includes `auth_time`, `amr`, `acr`, `at_hash` (access token hash), and optionally `nonce`.

## Access Token

An access token is an opaque bearer token that grants the holder access to protected resources. In Barycenter, access tokens are random strings (24 random bytes, Base64url-encoded) stored in the database with an associated subject, scope, and expiration. They are used to call the `/userinfo` endpoint and can be presented to resource servers that validate them against Barycenter.

## Refresh Token

A refresh token is a long-lived credential that allows a client to obtain new access tokens without requiring the user to re-authenticate. Barycenter implements refresh token rotation: each time a refresh token is used, a new one is issued and the old one is invalidated. This limits the window of exposure if a refresh token is compromised.

## JWKS (JSON Web Key Set)

A JWKS is a JSON document containing the public keys used to verify JWT signatures. Barycenter publishes its JWKS at `/.well-known/jwks.json`. Relying parties fetch this endpoint to obtain the public key matching the `kid` in the ID Token header, then use it to verify the token's RS256 signature. Barycenter generates a 2048-bit RSA key pair on first startup and persists it to disk.

## KDL (KDL Document Language)

KDL is a document language designed to be a more human-friendly alternative to XML, JSON, or TOML for configuration files. Barycenter uses KDL to define authorization policies in its built-in policy engine. Policy files are stored in a configurable directory and evaluated by the authorization server.

## ReBAC (Relationship-Based Access Control)

ReBAC is an access control model where authorization decisions are based on the relationships between entities. For example, "user A can edit document B because user A is a member of group C, and group C has edit access to document B." Barycenter's policy engine supports ReBAC patterns in its KDL policy definitions.

## ABAC (Attribute-Based Access Control)

ABAC is an access control model where authorization decisions are based on attributes of the subject (user), the resource, the action, and the environment. For example, "allow access if the user's department is 'engineering' and the resource is tagged 'internal' and the current time is within business hours." Barycenter's policy engine combines ABAC with ReBAC for flexible authorization rules.
