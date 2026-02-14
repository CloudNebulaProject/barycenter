# Glossary

Definitions of terms used throughout the Barycenter documentation, listed alphabetically.

---

**AAL (Authenticator Assurance Level)**
: A NIST SP 800-63B classification describing the strength of an authentication event. AAL1 requires single-factor authentication. AAL2 requires two distinct authentication factors. Barycenter maps these to the `acr` claim values `"aal1"` and `"aal2"`.

**ABAC (Attribute-Based Access Control)**
: An access control model that evaluates policies based on attributes of the subject, resource, action, and environment. Contrasts with ReBAC, which uses relationships. The Barycenter authorization policy server supports both models.

**Access Token**
: A credential issued by the token endpoint that authorizes the bearer to access protected resources. In Barycenter, access tokens are opaque strings (not JWTs) with a 1-hour lifetime. They are validated by looking up the token in the database and checking expiration and revocation status.

**ACR (Authentication Context Class Reference)**
: An identifier in the ID Token (`acr` claim) indicating the authentication assurance level achieved. Barycenter issues `"aal1"` for single-factor authentication and `"aal2"` for two-factor authentication.

**AMR (Authentication Methods References)**
: A JSON array in the ID Token (`amr` claim) listing the authentication methods used during the session. Barycenter uses the values `"pwd"` (password), `"hwk"` (hardware-bound passkey), and `"swk"` (cloud-synced passkey). Multiple values indicate multi-factor authentication.

**at_hash (Access Token Hash)**
: A claim in the ID Token containing the left half of the SHA-256 hash of the access token value, base64url-encoded. Allows the client to verify that the ID Token and access token were issued together. Defined in OpenID Connect Core 1.0.

**Authorization Code**
: A short-lived, single-use credential issued by the authorization endpoint and exchanged at the token endpoint for access and ID tokens. In Barycenter, authorization codes expire after 5 minutes and are marked as consumed after a single exchange.

**Bearer Token**
: An access token scheme where any party in possession of the token can use it to access the associated resources. Transmitted in the HTTP `Authorization` header as `Bearer <token>`. Defined in RFC 6750.

**Claims**
: Name-value pairs about an entity (typically a user) included in tokens or returned from the UserInfo endpoint. Standard OIDC claims include `sub`, `name`, `email`, `auth_time`, and others.

**Consent**
: The user's explicit approval for a client application to access specific scopes on their behalf. Barycenter presents a consent page during the authorization flow and stores consent decisions so that returning users are not prompted again for the same client and scopes.

**FIDO2**
: A set of specifications from the FIDO Alliance for strong authentication, comprising the WebAuthn browser API and the CTAP (Client to Authenticator Protocol). FIDO2 enables passwordless and multi-factor authentication using public-key cryptography.

**GraphQL**
: A query language and runtime for APIs developed by Facebook. Barycenter uses GraphQL for the admin management APIs, serving both a Seaography entity CRUD API and a job management API.

**ID Token**
: A JSON Web Token (JWT) issued by the token endpoint that contains claims about the authentication event and the authenticated user. It is signed with the provider's private key and verified by clients using the public key from the JWKS endpoint.

**IdP (Identity Provider)**
: A system that authenticates users and issues identity assertions to relying parties. Barycenter functions as an OpenID Connect Identity Provider.

**Implicit Flow**
: An OAuth 2.0 flow where tokens are returned directly from the authorization endpoint via the URL fragment, without a token endpoint exchange. Barycenter supports the `id_token` and `id_token token` response types. The implicit flow is considered less secure than the authorization code flow with PKCE and is primarily supported for legacy compatibility.

**JWK (JSON Web Key)**
: A JSON data structure representing a single cryptographic key. Defined in RFC 7517. Barycenter publishes its RSA public key as a JWK.

**JWKS (JSON Web Key Set)**
: A JSON data structure containing a set of JWKs, published at the `/.well-known/jwks.json` endpoint. Clients retrieve the JWKS to obtain the public keys needed to verify ID Token signatures. Defined in RFC 7517.

**JWT (JSON Web Token)**
: A compact, URL-safe token format for transmitting claims between parties. Consists of a header, payload, and signature, each base64url-encoded and separated by dots. Defined in RFC 7519. Barycenter uses JWTs for ID Tokens.

**KDL**
: A document language designed for configuration files and data serialization. Used by the Barycenter authorization policy server for defining authorization policies.

**Nonce**
: An opaque string value provided by the client in the authorization request and echoed back in the ID Token. Used to mitigate replay attacks by allowing the client to verify that the ID Token was issued in response to its specific request.

**OAuth 2.0**
: An authorization framework defined in RFC 6749 that enables third-party applications to obtain limited access to an HTTP service. Barycenter implements the authorization code, refresh token, device authorization, and implicit grant types.

**OIDC (OpenID Connect)**
: An identity layer built on top of OAuth 2.0, defined by the OpenID Foundation. OIDC adds authentication semantics to OAuth 2.0 through ID Tokens, a UserInfo endpoint, and discovery metadata. Barycenter is an OpenID Connect Provider (OP).

**Passkey**
: A FIDO2-based credential that replaces passwords with public-key cryptography. Passkeys can be hardware-bound (e.g., YubiKey) or cloud-synced (e.g., iCloud Keychain, Google Password Manager). Barycenter supports passkeys for both primary authentication and as a second factor.

**PKCE (Proof Key for Code Exchange)**
: An extension to the OAuth 2.0 authorization code flow (RFC 7636) that prevents authorization code interception attacks. The client generates a random `code_verifier`, sends its SHA-256 hash as the `code_challenge` during authorization, and proves possession of the verifier during token exchange. Barycenter requires PKCE with the S256 method for all authorization code flows.

**ReBAC (Relationship-Based Access Control)**
: An access control model that makes authorization decisions based on relationships between entities. For example, "user A is a viewer of document B." The Barycenter authorization policy server implements ReBAC through relationship tuples.

**Refresh Token**
: A long-lived credential issued alongside the access token that can be exchanged for a new access token when the current one expires. Barycenter implements refresh token rotation: each use of a refresh token invalidates the old token and issues a new one.

**Relationship Tuple**
: A data structure in ReBAC systems representing a relationship between a subject and an object, in the form `(object, relation, subject)`. For example, `(document:readme, viewer, user:alice)` means Alice is a viewer of the readme document.

**RP (Relying Party)**
: An application that relies on an Identity Provider for authentication. In the OIDC context, a relying party is an OAuth 2.0 client that receives and validates ID Tokens from the provider. Also referred to as a "client" in OAuth 2.0 terminology.

**RS256**
: An asymmetric signing algorithm that uses RSA with SHA-256. The provider signs tokens with its private RSA key, and clients verify signatures using the corresponding public key from the JWKS. Barycenter uses RS256 as its default (and currently only) signing algorithm.

**Scope**
: A mechanism for limiting the access granted to an access token. In OIDC, the `openid` scope is required and triggers ID Token issuance. Additional scopes like `profile` and `email` control which claims are returned. Barycenter recognizes high-value scopes (`admin`, `payment`, `transfer`, `delete`) that trigger context-based 2FA.

**Seaography**
: A library that generates a GraphQL API from SeaORM entities. Barycenter uses Seaography to automatically provide CRUD operations on all database entities via the admin API.

**Userset**
: In ReBAC, a set of subjects derived from a relationship. For example, `group:engineering#member` refers to all members of the engineering group. Usersets enable indirect relationships and permission inheritance in the authorization policy server.

**WASM (WebAssembly)**
: A binary instruction format for a stack-based virtual machine, designed for near-native execution in web browsers. Barycenter compiles a Rust client (`client-wasm/`) to WebAssembly for performing browser-side WebAuthn operations, including credential creation and assertion.

**WebAuthn (Web Authentication)**
: A W3C specification (part of FIDO2) that defines a browser API for creating and using public-key credentials. WebAuthn enables passwordless authentication and strong multi-factor authentication. Barycenter implements both registration and authentication ceremonies through its `/webauthn/*` endpoints.
