use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Create trusted_peers table
        db.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS trusted_peers (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                issuer_url TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_secret TEXT,
                token_endpoint TEXT,
                authorization_endpoint TEXT,
                userinfo_endpoint TEXT,
                jwks_uri TEXT,
                pinned_jwks TEXT,
                jwks_pin_mode TEXT NOT NULL DEFAULT 'pin_on_first_use',
                scopes TEXT NOT NULL DEFAULT 'openid email profile',
                mapping_policy TEXT NOT NULL DEFAULT 'existing_only',
                trust_peer_acr BOOLEAN NOT NULL DEFAULT 0,
                sync_profile BOOLEAN NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending_verification',
                verification_level TEXT,
                verified_at TEXT,
                webfinger_issuer_match BOOLEAN,
                last_discovery_refresh TEXT,
                last_discovery_error TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )",
        )
        .await?;

        // Create federated_identities table
        db.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS federated_identities (
                id TEXT PRIMARY KEY,
                local_user_id TEXT NOT NULL,
                peer_id TEXT NOT NULL,
                external_subject TEXT NOT NULL,
                external_issuer TEXT NOT NULL,
                external_email TEXT,
                linked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_login_at TEXT,
                FOREIGN KEY (peer_id) REFERENCES trusted_peers(id) ON DELETE CASCADE,
                UNIQUE(peer_id, external_subject)
            )",
        )
        .await?;

        // Create federation_auth_requests table
        db.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS federation_auth_requests (
                id TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                state TEXT NOT NULL UNIQUE,
                nonce TEXT NOT NULL,
                pkce_verifier TEXT NOT NULL,
                original_authorize_params TEXT NOT NULL,
                original_session_id TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                expires_at TEXT NOT NULL,
                FOREIGN KEY (peer_id) REFERENCES trusted_peers(id) ON DELETE CASCADE
            )",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared("DROP TABLE IF EXISTS federation_auth_requests")
            .await?;
        db.execute_unprepared("DROP TABLE IF EXISTS federated_identities")
            .await?;
        db.execute_unprepared("DROP TABLE IF EXISTS trusted_peers")
            .await?;

        Ok(())
    }
}
