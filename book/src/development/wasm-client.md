# WASM Client

Barycenter includes a Rust-based WebAssembly client that provides browser-side WebAuthn/passkey functionality. The client is compiled from Rust to WebAssembly using `wasm-pack` and loaded by the login and account management pages.

## Building

### Prerequisites

Install `wasm-pack` if you do not already have it:

```bash
cargo install wasm-pack
```

### Build Command

```bash
cd client-wasm
wasm-pack build --target web --out-dir ../static/wasm
```

The `--target web` flag generates ES module output suitable for loading directly in a browser with `<script type="module">`.

The `--out-dir ../static/wasm` flag places the output in the `static/wasm/` directory, where Barycenter's web server serves static files from.

### Output Files

After building, the following files are generated in `static/wasm/`:

| File | Description |
|------|-------------|
| `barycenter_webauthn_client_bg.wasm` | The compiled WebAssembly binary |
| `barycenter_webauthn_client.js` | JavaScript glue code (ES module) that loads and initializes the WASM binary |
| `barycenter_webauthn_client.d.ts` | TypeScript type definitions for the exported API |
| `barycenter_webauthn_client_bg.wasm.d.ts` | TypeScript type definitions for the WASM binary |

## Module API

The WASM module exports four functions that the browser-side JavaScript calls:

### `supports_webauthn()`

Checks whether the browser supports the WebAuthn API.

```javascript
import init, { supports_webauthn } from '/static/wasm/barycenter_webauthn_client.js';

await init();

if (supports_webauthn()) {
    // Browser supports WebAuthn, enable passkey features
}
```

Returns `true` if `navigator.credentials` is available and supports the `create` and `get` operations.

### `supports_conditional_ui()`

Checks whether the browser supports conditional UI (autofill) for passkeys. This is an async check because the capability detection requires querying the browser.

```javascript
import init, { supports_conditional_ui } from '/static/wasm/barycenter_webauthn_client.js';

await init();

if (await supports_conditional_ui()) {
    // Browser supports passkey autofill (Chrome 108+, Safari 16+)
}
```

Conditional UI allows passkeys to appear in the browser's autofill dropdown when the user focuses on a username field, providing a seamless authentication experience without a separate "Sign in with passkey" button.

### `register_passkey(options)`

Creates a new passkey credential. Called during the passkey registration flow after the server provides creation options.

```javascript
import init, { register_passkey } from '/static/wasm/barycenter_webauthn_client.js';

await init();

// 1. Start registration on the server
const response = await fetch('/webauthn/register/start', { method: 'POST' });
const options = await response.json();

// 2. Create the credential in the browser
const credential = await register_passkey(options);

// 3. Send the credential back to the server
await fetch('/webauthn/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential)
});
```

This function wraps the browser's `navigator.credentials.create()` API, handling the conversion between the server's JSON format and the browser's `PublicKeyCredentialCreationOptions`.

### `authenticate_passkey(options, mediation)`

Authenticates using an existing passkey. The `mediation` parameter controls whether to use conditional UI (autofill) or a modal prompt.

```javascript
import init, { authenticate_passkey } from '/static/wasm/barycenter_webauthn_client.js';

await init();

// 1. Start authentication on the server
const response = await fetch('/webauthn/authenticate/start', { method: 'POST' });
const options = await response.json();

// 2. Authenticate with a passkey
// mediation: "conditional" for autofill, "optional" for modal prompt
const assertion = await authenticate_passkey(options, "conditional");

// 3. Send the assertion back to the server
await fetch('/webauthn/authenticate/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(assertion)
});
```

**Mediation values:**

| Value | Behavior |
|-------|----------|
| `"conditional"` | Passkeys appear in the browser's autofill dropdown. Non-blocking -- the user can choose to type a password instead. |
| `"optional"` | Shows a modal browser dialog prompting the user to select a passkey. Used for explicit "Sign in with passkey" buttons. |

## Browser Integration

### Loading the Module

The WASM module is loaded as an ES module in the login page:

```html
<script type="module">
    import init, {
        supports_webauthn,
        supports_conditional_ui,
        authenticate_passkey
    } from '/static/wasm/barycenter_webauthn_client.js';

    async function setup() {
        await init();

        if (!supports_webauthn()) {
            // Hide passkey UI elements
            return;
        }

        if (await supports_conditional_ui()) {
            // Start conditional UI (autofill) authentication
            startConditionalAuth();
        } else {
            // Show explicit "Sign in with passkey" button
            showPasskeyButton();
        }
    }

    setup();
</script>
```

### Content-Security-Policy Requirement

The WASM module requires the `wasm-unsafe-eval` CSP directive. Barycenter's security headers include this:

```
script-src 'self' 'wasm-unsafe-eval'
```

Without `wasm-unsafe-eval`, the browser blocks WebAssembly compilation. This directive is narrowly scoped and does not permit JavaScript `eval()`.

### Browser Compatibility

| Browser | WebAuthn | Conditional UI (Autofill) |
|---------|----------|--------------------------|
| Chrome 108+ | Yes | Yes |
| Safari 16+ | Yes | Yes |
| Firefox 119+ | Yes | No |
| Edge 108+ | Yes | Yes |

On browsers that do not support conditional UI, the login page falls back to showing an explicit "Sign in with passkey" button. On browsers without WebAuthn support, passkey features are hidden entirely and password authentication remains available.

## Development Workflow

During development, rebuild the WASM module whenever you change the `client-wasm/` source:

```bash
cd client-wasm
wasm-pack build --target web --out-dir ../static/wasm
```

The WASM output files are not checked into version control. They must be built locally or generated as part of the CI/CD pipeline before deploying.
