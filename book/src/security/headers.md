# Security Headers

Barycenter applies a set of security headers to every HTTP response through its middleware layer. These headers instruct browsers to enforce restrictions that mitigate common web vulnerabilities.

## Header Summary

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | `DENY` | Prevents the page from being rendered in iframes, blocking clickjacking attacks |
| `X-Content-Type-Options` | `nosniff` | Prevents browsers from MIME-sniffing the response away from the declared Content-Type |
| `X-XSS-Protection` | `1; mode=block` | Enables legacy browser XSS filters; instructs the browser to block the page rather than sanitize |
| `Content-Security-Policy` | See [CSP Breakdown](#content-security-policy-breakdown) | Controls which resources the browser is allowed to load, preventing XSS and data injection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Sends the full URL as referrer for same-origin requests, but only the origin for cross-origin requests |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Disables access to device APIs that the application does not use |

## Header Details

### X-Frame-Options: DENY

This header prevents any site (including Barycenter itself) from embedding Barycenter pages in an `<iframe>`, `<frame>`, or `<object>` element. The `DENY` value is the strictest setting, chosen because Barycenter has no legitimate use case for being framed.

This protects against clickjacking, where an attacker overlays a transparent Barycenter page on top of a deceptive UI to trick users into performing unintended actions (such as approving an authorization request).

### X-Content-Type-Options: nosniff

Prevents the browser from performing MIME type sniffing on responses. Without this header, a browser might interpret a file as a different content type than declared, potentially executing malicious content. For example, a response with `Content-Type: text/plain` could be sniffed as HTML and executed.

### X-XSS-Protection: 1; mode=block

This header enables the XSS filter built into older browsers (primarily Internet Explorer and older Chrome versions). The `mode=block` directive tells the browser to block rendering entirely rather than attempting to sanitize the page.

While modern browsers have deprecated this filter in favor of Content-Security-Policy, it remains useful as a defense-in-depth measure for users on older browsers.

### Referrer-Policy: strict-origin-when-cross-origin

Controls how much referrer information is included in requests:

- **Same-origin requests**: Full URL is sent (e.g., `https://idp.example.com/authorize?client_id=...`).
- **Cross-origin requests (HTTPS to HTTPS)**: Only the origin is sent (e.g., `https://idp.example.com`).
- **Cross-origin requests (HTTPS to HTTP)**: No referrer is sent.

This prevents sensitive information in URL query parameters (such as authorization codes or state values) from leaking to third-party sites through the Referer header.

### Permissions-Policy: geolocation=(), microphone=(), camera=()

Explicitly disables browser APIs that Barycenter does not use. The empty parentheses `()` mean these features are disabled for all origins, including the page itself. This reduces the attack surface by ensuring that even if an XSS vulnerability were exploited, the attacker could not access device sensors.

## Content-Security-Policy Breakdown

The Content-Security-Policy (CSP) header is the most complex security header. Barycenter uses the following policy:

```
default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'
```

Each directive controls a specific resource type:

| Directive | Value | What It Controls |
|-----------|-------|-----------------|
| `default-src` | `'self'` | Fallback for all resource types not explicitly listed. Only allows resources from the same origin. |
| `script-src` | `'self' 'wasm-unsafe-eval'` | JavaScript execution. Allows scripts from the same origin. The `wasm-unsafe-eval` token permits WebAssembly compilation and execution, which is required for the passkey WASM client. |
| `style-src` | `'self' 'unsafe-inline'` | CSS stylesheets. Allows stylesheets from the same origin and inline `<style>` elements. Inline styles are permitted because the login and account pages use inline CSS for layout. |
| `img-src` | `'self' data:` | Image sources. Allows images from the same origin and `data:` URIs (used for inline SVG icons and small images). |
| `form-action` | `'self'` | Form submission targets. Ensures that HTML forms can only submit to the same origin, preventing form hijacking attacks. |

### Why wasm-unsafe-eval?

The `wasm-unsafe-eval` CSP directive is required because Barycenter uses a Rust-compiled WebAssembly module for passkey/WebAuthn operations in the browser. Without this directive, the browser would block WASM compilation. The `wasm-unsafe-eval` token is narrowly scoped: it only permits WebAssembly instantiation and does not allow JavaScript `eval()` or `Function()` constructor use.

### Directives Not Explicitly Set

The following directives inherit the `default-src 'self'` restriction:

- `connect-src` -- Fetch/XHR requests are limited to the same origin (used for WebAuthn API calls).
- `font-src` -- Fonts must come from the same origin.
- `frame-src` -- No iframes are allowed (reinforces X-Frame-Options).
- `frame-ancestors` -- Implicitly set to `'self'` by `default-src`, preventing framing by other origins.
- `object-src` -- Plugin content (Flash, Java applets) is blocked.
- `media-src` -- Audio and video elements are restricted to same origin.
