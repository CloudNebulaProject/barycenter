# WebAuthn Fixture Capture Tool

This tool captures real WebAuthn responses from your authenticator for use in integration tests.

## Prerequisites

1. Start Barycenter server:
   ```bash
   cargo run
   ```

2. Create a test user (if not already exists):
   ```bash
   # The default admin user should work (admin/password123)
   ```

## Usage

1. Open `capture_webauthn_fixture.html` in your browser:
   ```bash
   open tests/tools/capture_webauthn_fixture.html
   # or
   firefox tests/tools/capture_webauthn_fixture.html
   ```

2. Click "Login to Server" to authenticate

3. Click "Capture Registration Fixture" to register a new passkey
   - Your browser will prompt you to use your authenticator
   - Use TouchID, Windows Hello, or a USB security key

4. Copy the JSON output and save to `tests/fixtures/`

## Fixture Types

### Hardware-Bound Passkey
- **File**: `hardware_key_registration.json`
- **Device**: USB security key (YubiKey, etc.)
- **Characteristics**:
  - `backup_eligible`: false
  - `backup_state`: false
  - AMR: `["hwk"]`

### Cloud-Synced Passkey
- **File**: `cloud_synced_passkey.json`
- **Device**: TouchID (macOS), Windows Hello, iCloud Keychain
- **Characteristics**:
  - `backup_eligible`: true
  - `backup_state`: true
  - AMR: `["swk"]`

## Captured Data

Each fixture contains:
- **challenge_response**: The initial challenge from the server
- **credential_response**: The credential created by the authenticator
- **server_response**: The server's verification response (registration only)
- **metadata**: Capture timestamp, authenticator type, user agent

## Using Fixtures in Tests

```rust
use crate::helpers::load_fixture;

#[tokio::test]
async fn test_passkey_registration() {
    let fixture = load_fixture("hardware_key_registration");
    // Use fixture.challenge_response and fixture.credential_response in tests
}
```

## Tips

- **Multiple Devices**: Capture fixtures from different authenticator types (hardware vs platform)
- **Fresh Captures**: If the server's JWKS changes, you may need to recapture fixtures
- **Counter Values**: Each authentication increments the counter - recapture if needed for specific counter tests
