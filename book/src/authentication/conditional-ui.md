# Conditional UI / Autofill

Conditional UI is a WebAuthn feature that integrates passkey authentication into the browser's native autofill mechanism. Instead of requiring users to click a dedicated "Sign in with passkey" button, passkey credentials appear alongside saved passwords in the username field's autofill dropdown.

## How It Works

When the login page loads, Barycenter's WASM client:

1. Calls `supports_conditional_ui()` to check if the browser supports the feature.
2. If supported, initiates a passkey authentication request with `mediation: "conditional"`.
3. The browser silently prepares available passkeys for the current RP ID.
4. When the user focuses the username field, passkey credentials appear in the autofill dropdown alongside any saved passwords.
5. If the user selects a passkey, the WebAuthn assertion ceremony completes automatically.
6. If the user types a username and password instead, the passkey request is silently abandoned.

This approach is called **progressive enhancement**: passkey users get a streamlined experience, while password users see no difference from a traditional login form.

## Browser Support

Conditional UI support varies across browsers. The `supports_conditional_ui()` function in the WASM client detects availability at runtime.

| Browser             | Minimum Version | Status                          |
|---------------------|-----------------|---------------------------------|
| Google Chrome       | 108+            | Fully supported                 |
| Microsoft Edge      | 108+            | Fully supported (Chromium-based)|
| Apple Safari        | 16+             | Fully supported                 |
| Mozilla Firefox     | ---             | Not yet supported               |
| Safari (iOS)        | 16+             | Fully supported                 |
| Chrome (Android)    | 108+            | Fully supported                 |

> **Note**: Browser support is checked at runtime. The table above reflects the state at time of writing and may change as browsers add support. The `supports_conditional_ui()` function is the authoritative check.

## WASM Client Detection

The WASM client provides two capability-check functions:

```javascript
import init, {
  supports_webauthn,
  supports_conditional_ui
} from '/static/wasm/barycenter_webauthn_client.js';

await init();

// Check basic WebAuthn support
if (!supports_webauthn()) {
  // Hide all passkey UI elements
  // Show password-only login form
}

// Check Conditional UI support
if (await supports_conditional_ui()) {
  // Start conditional mediation (autofill mode)
  authenticate_passkey(options, "conditional");
} else {
  // Show explicit "Sign in with passkey" button
}
```

`supports_conditional_ui()` is an async function because it calls `PublicKeyCredential.isConditionalMediationAvailable()`, which returns a Promise.

## Autofill Integration

For Conditional UI to work, the login form's username input must include the `webauthn` autocomplete token:

```html
<input
  type="text"
  name="username"
  autocomplete="username webauthn"
  placeholder="Username"
/>
```

The `webauthn` token tells the browser to include passkey credentials in the autofill dropdown for this field. Without it, the browser will only show saved passwords.

Barycenter's built-in login page includes this attribute automatically.

## Mediation Modes

The WASM client's `authenticate_passkey()` function accepts a mediation parameter that controls how the browser presents credentials:

| Mode            | Behavior                                                         | Use Case                    |
|-----------------|------------------------------------------------------------------|-----------------------------|
| `"conditional"` | Credentials appear in the autofill dropdown, no modal.           | Default on page load.       |
| `"optional"`    | A modal dialog prompts the user to select a credential.          | Explicit button click.      |

### Conditional Mediation

```javascript
// Called on page load -- non-blocking, waits for autofill interaction
const assertion = await authenticate_passkey(options, "conditional");
```

The conditional request is initiated as soon as the page loads but does not block or show any UI. It remains pending until the user interacts with the autofill dropdown or the page navigates away.

### Optional Mediation (Fallback Button)

```javascript
// Called when user clicks "Sign in with passkey" button
const assertion = await authenticate_passkey(options, "optional");
```

This triggers the browser's standard modal credential picker. It is used as a fallback when Conditional UI is not supported or when the user explicitly requests passkey authentication.

## Fallback Strategy

Barycenter's login page implements a layered fallback strategy:

```
Browser supports Conditional UI?
  |
  +-- Yes --> Autofill mode (passkeys in dropdown + password form)
  |
  +-- No --> Browser supports WebAuthn?
              |
              +-- Yes --> Explicit "Sign in with passkey" button + password form
              |
              +-- No --> Password-only form
```

This ensures that every user can authenticate regardless of their browser's capabilities. The login page adapts its UI based on the detected support level without requiring any user configuration.
