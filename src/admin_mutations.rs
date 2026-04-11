use async_graphql::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, Set,
};
use std::sync::Arc;

use crate::entities;
use crate::federation;
use crate::jobs;
use crate::jwks::JwksManager;
use crate::settings::Settings;
use crate::storage;

/// Custom mutations for admin operations
#[derive(Default)]
pub struct AdminMutation;

#[Object]
impl AdminMutation {
    /// Manually trigger a background job by name
    async fn trigger_job(&self, ctx: &Context<'_>, job_name: String) -> Result<JobTriggerResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        match jobs::trigger_job_manually(db.as_ref(), &job_name).await {
            Ok(_) => Ok(JobTriggerResult {
                success: true,
                message: format!("Job '{}' triggered successfully", job_name),
                job_name,
            }),
            Err(e) => Ok(JobTriggerResult {
                success: false,
                message: format!("Failed to trigger job '{}': {}", job_name, e),
                job_name,
            }),
        }
    }

    /// Add a trusted federation peer
    #[graphql(name = "addTrustedPeer")]
    #[allow(clippy::too_many_arguments)]
    async fn add_trusted_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer")] domain: String,
        #[graphql(desc = "Issuer URL of the peer")] issuer_url: String,
        #[graphql(desc = "OAuth client_id registered at the peer")] client_id: String,
        #[graphql(desc = "OAuth client_secret registered at the peer")] client_secret: Option<
            String,
        >,
        #[graphql(desc = "Pinned JWKS JSON document")] pinned_jwks: Option<String>,
        #[graphql(
            desc = "Mapping policy (prompt | auto_link | auto_create)",
            default_with = "Some(\"prompt\".to_string())"
        )]
        mapping_policy: Option<String>,
        #[graphql(desc = "Skip verification and set active immediately")] manual_override: Option<
            bool,
        >,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let mapping = mapping_policy.unwrap_or_else(|| "prompt".to_string());
        let manual = manual_override.unwrap_or(false);

        // Create the peer record
        let peer_id = federation::storage::create_trusted_peer(
            db.as_ref(),
            &domain,
            &issuer_url,
            &client_id,
            client_secret.as_deref(),
            &mapping,
            "pin_on_first_use",
        )
        .await
        .map_err(|e| Error::new(format!("Failed to create peer: {}", e)))?;

        if manual {
            // Manual override: set active + manual_override verification level
            federation::storage::update_trusted_peer_status(db.as_ref(), &peer_id, "active")
                .await
                .map_err(|e| Error::new(format!("Failed to update status: {}", e)))?;
            federation::storage::update_trusted_peer_verification(
                db.as_ref(),
                &peer_id,
                Some("manual_override"),
                None,
            )
            .await
            .map_err(|e| Error::new(format!("Failed to update verification: {}", e)))?;

            let peer = federation::storage::get_trusted_peer_by_id(db.as_ref(), &peer_id)
                .await
                .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

            return Ok(PeerOperationResult {
                success: true,
                message: format!("Peer '{}' added with manual override", domain),
                peer: peer.as_ref().map(TrustedPeerGql::from),
            });
        }

        // Run verification
        match federation::verification::verify_peer(&domain, &issuer_url).await {
            Ok(result) => {
                // Update discovery data
                federation::storage::update_trusted_peer_discovery(
                    db.as_ref(),
                    &peer_id,
                    Some(&result.token_endpoint),
                    Some(&result.authorization_endpoint),
                    result.userinfo_endpoint.as_deref(),
                    Some(&result.jwks_uri),
                    pinned_jwks.as_deref().or(result.pinned_jwks.as_deref()),
                )
                .await
                .map_err(|e| Error::new(format!("Failed to update discovery: {}", e)))?;

                // Update verification info
                federation::storage::update_trusted_peer_verification(
                    db.as_ref(),
                    &peer_id,
                    Some(&result.verification_level),
                    Some(result.webfinger_issuer_match),
                )
                .await
                .map_err(|e| Error::new(format!("Failed to update verification: {}", e)))?;

                // Set active
                federation::storage::update_trusted_peer_status(db.as_ref(), &peer_id, "active")
                    .await
                    .map_err(|e| Error::new(format!("Failed to update status: {}", e)))?;

                let peer = federation::storage::get_trusted_peer_by_id(db.as_ref(), &peer_id)
                    .await
                    .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                Ok(PeerOperationResult {
                    success: true,
                    message: format!("Peer '{}' verified and activated", domain),
                    peer: peer.as_ref().map(TrustedPeerGql::from),
                })
            }
            Err(e) => {
                // Leave as pending_verification, store error
                let peer = federation::storage::get_trusted_peer_by_id(db.as_ref(), &peer_id)
                    .await
                    .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                Ok(PeerOperationResult {
                    success: false,
                    message: format!("Verification failed: {}", e),
                    peer: peer.as_ref().map(TrustedPeerGql::from),
                })
            }
        }
    }

    /// Remove a trusted federation peer
    #[graphql(name = "removeTrustedPeer")]
    async fn remove_trusted_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer to remove")] domain: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match peer {
            Some(p) => {
                federation::storage::delete_trusted_peer(db.as_ref(), &p.id)
                    .await
                    .map_err(|e| Error::new(format!("Failed to delete peer: {}", e)))?;

                Ok(PeerOperationResult {
                    success: true,
                    message: format!("Peer '{}' removed", domain),
                    peer: None,
                })
            }
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer '{}' not found", domain),
                peer: None,
            }),
        }
    }

    /// Suspend a trusted federation peer
    #[graphql(name = "suspendTrustedPeer")]
    async fn suspend_trusted_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer to suspend")] domain: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match peer {
            Some(p) => {
                federation::storage::update_trusted_peer_status(db.as_ref(), &p.id, "suspended")
                    .await
                    .map_err(|e| Error::new(format!("Failed to update status: {}", e)))?;

                let updated = federation::storage::get_trusted_peer_by_id(db.as_ref(), &p.id)
                    .await
                    .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                Ok(PeerOperationResult {
                    success: true,
                    message: format!("Peer '{}' suspended", domain),
                    peer: updated.as_ref().map(TrustedPeerGql::from),
                })
            }
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer '{}' not found", domain),
                peer: None,
            }),
        }
    }

    /// Activate a trusted federation peer (re-runs verification)
    #[graphql(name = "activateTrustedPeer")]
    async fn activate_trusted_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer to activate")] domain: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match peer {
            Some(p) => {
                match federation::verification::verify_peer(&p.domain, &p.issuer_url).await {
                    Ok(result) => {
                        federation::storage::update_trusted_peer_discovery(
                            db.as_ref(),
                            &p.id,
                            Some(&result.token_endpoint),
                            Some(&result.authorization_endpoint),
                            result.userinfo_endpoint.as_deref(),
                            Some(&result.jwks_uri),
                            result.pinned_jwks.as_deref(),
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update discovery: {}", e)))?;

                        federation::storage::update_trusted_peer_verification(
                            db.as_ref(),
                            &p.id,
                            Some(&result.verification_level),
                            Some(result.webfinger_issuer_match),
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update verification: {}", e)))?;

                        federation::storage::update_trusted_peer_status(
                            db.as_ref(),
                            &p.id,
                            "active",
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update status: {}", e)))?;

                        let updated =
                            federation::storage::get_trusted_peer_by_id(db.as_ref(), &p.id)
                                .await
                                .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                        Ok(PeerOperationResult {
                            success: true,
                            message: format!("Peer '{}' verified and activated", domain),
                            peer: updated.as_ref().map(TrustedPeerGql::from),
                        })
                    }
                    Err(e) => Ok(PeerOperationResult {
                        success: false,
                        message: format!("Verification failed: {}", e),
                        peer: Some(TrustedPeerGql::from(&p)),
                    }),
                }
            }
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer '{}' not found", domain),
                peer: None,
            }),
        }
    }

    /// Refresh discovery data for a trusted peer
    #[graphql(name = "refreshPeerDiscovery")]
    async fn refresh_peer_discovery(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer")] domain: String,
        #[graphql(desc = "Update pinned JWKS from fresh fetch")] update_pin: Option<bool>,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match peer {
            Some(p) => {
                match federation::verification::verify_peer(&p.domain, &p.issuer_url).await {
                    Ok(result) => {
                        let pin_jwks = if update_pin.unwrap_or(false) {
                            result.pinned_jwks.as_deref()
                        } else {
                            // Keep existing pin
                            None
                        };

                        federation::storage::update_trusted_peer_discovery(
                            db.as_ref(),
                            &p.id,
                            Some(&result.token_endpoint),
                            Some(&result.authorization_endpoint),
                            result.userinfo_endpoint.as_deref(),
                            Some(&result.jwks_uri),
                            pin_jwks,
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update discovery: {}", e)))?;

                        let updated =
                            federation::storage::get_trusted_peer_by_id(db.as_ref(), &p.id)
                                .await
                                .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                        Ok(PeerOperationResult {
                            success: true,
                            message: format!("Discovery refreshed for peer '{}'", domain),
                            peer: updated.as_ref().map(TrustedPeerGql::from),
                        })
                    }
                    Err(e) => Ok(PeerOperationResult {
                        success: false,
                        message: format!("Discovery refresh failed: {}", e),
                        peer: Some(TrustedPeerGql::from(&p)),
                    }),
                }
            }
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer '{}' not found", domain),
                peer: None,
            }),
        }
    }

    /// Re-verify a trusted peer (updates verification level)
    #[graphql(name = "reverifyPeer")]
    async fn reverify_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer")] domain: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match peer {
            Some(p) => {
                match federation::verification::verify_peer(&p.domain, &p.issuer_url).await {
                    Ok(result) => {
                        federation::storage::update_trusted_peer_discovery(
                            db.as_ref(),
                            &p.id,
                            Some(&result.token_endpoint),
                            Some(&result.authorization_endpoint),
                            result.userinfo_endpoint.as_deref(),
                            Some(&result.jwks_uri),
                            result.pinned_jwks.as_deref(),
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update discovery: {}", e)))?;

                        federation::storage::update_trusted_peer_verification(
                            db.as_ref(),
                            &p.id,
                            Some(&result.verification_level),
                            Some(result.webfinger_issuer_match),
                        )
                        .await
                        .map_err(|e| Error::new(format!("Failed to update verification: {}", e)))?;

                        let updated =
                            federation::storage::get_trusted_peer_by_id(db.as_ref(), &p.id)
                                .await
                                .map_err(|e| Error::new(format!("Failed to fetch peer: {}", e)))?;

                        Ok(PeerOperationResult {
                            success: true,
                            message: format!(
                                "Peer '{}' re-verified (level: {})",
                                domain, result.verification_level
                            ),
                            peer: updated.as_ref().map(TrustedPeerGql::from),
                        })
                    }
                    Err(e) => Ok(PeerOperationResult {
                        success: false,
                        message: format!("Re-verification failed: {}", e),
                        peer: Some(TrustedPeerGql::from(&p)),
                    }),
                }
            }
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer '{}' not found", domain),
                peer: None,
            }),
        }
    }

    /// Set 2FA requirement for a user (admin-enforced 2FA)
    async fn set_user_2fa_required(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Username to modify")] username: String,
        #[graphql(desc = "Whether 2FA should be required")] required: bool,
    ) -> Result<User2FAResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        // Get user by username
        let user = storage::get_user_by_username(db.as_ref(), &username)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new(format!("User '{}' not found", username)))?;

        // Update requires_2fa flag
        use crate::entities::user::{Column, Entity};
        let user_entity = Entity::find()
            .filter(Column::Subject.eq(&user.subject))
            .one(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new("User entity not found"))?;

        let mut active: entities::user::ActiveModel = user_entity.into_active_model();
        active.requires_2fa = Set(if required { 1 } else { 0 });

        active
            .update(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Failed to update user: {}", e)))?;

        Ok(User2FAResult {
            success: true,
            message: format!(
                "2FA requirement {} for user '{}'",
                if required { "enabled" } else { "disabled" },
                username
            ),
            username,
            requires_2fa: required,
        })
    }

    /// Initiate mutual peering with a remote peer.
    ///
    /// This auto-registers at the peer's /connect/register, then sends
    /// a signed peer-request JWS. The local peer is stored with status
    /// `pending_mutual` until the remote admin approves.
    #[graphql(name = "initiatePeering")]
    async fn initiate_peering(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Issuer URL of the remote peer")] peer_issuer_url: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;
        let jwks = ctx
            .data::<JwksManager>()
            .map_err(|_| Error::new("JwksManager not available"))?;
        let settings = ctx
            .data::<Arc<Settings>>()
            .map_err(|_| Error::new("Settings not available"))?;

        if !settings.federation.enabled {
            return Ok(PeerOperationResult {
                success: false,
                message: "Federation is not enabled".to_string(),
                peer: None,
            });
        }

        match federation::peering::initiate_peering(
            db.as_ref(),
            jwks,
            settings.as_ref(),
            &peer_issuer_url,
        )
        .await
        {
            Ok(result) => {
                let peer = federation::storage::get_trusted_peer_by_domain(
                    db.as_ref(),
                    &result.peer_domain,
                )
                .await
                .ok()
                .flatten();

                Ok(PeerOperationResult {
                    success: true,
                    message: format!(
                        "Peering initiated with {}. Status: {}. Waiting for remote admin approval.",
                        result.peer_domain, result.status
                    ),
                    peer: peer.as_ref().map(TrustedPeerGql::from),
                })
            }
            Err(e) => Ok(PeerOperationResult {
                success: false,
                message: format!("Failed to initiate peering: {}", e),
                peer: None,
            }),
        }
    }

    /// Approve an incoming peer request.
    ///
    /// This auto-registers at the requester's /connect/register, creates
    /// a trusted peer with status `active`, and sends a signed peer-confirm.
    #[graphql(name = "approvePeerRequest")]
    async fn approve_peer_request(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "ID of the peer request to approve")] request_id: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;
        let jwks = ctx
            .data::<JwksManager>()
            .map_err(|_| Error::new("JwksManager not available"))?;
        let settings = ctx
            .data::<Arc<Settings>>()
            .map_err(|_| Error::new("Settings not available"))?;

        if !settings.federation.enabled {
            return Ok(PeerOperationResult {
                success: false,
                message: "Federation is not enabled".to_string(),
                peer: None,
            });
        }

        match federation::peering::approve_peer_request(
            db.as_ref(),
            jwks,
            settings.as_ref(),
            &request_id,
        )
        .await
        {
            Ok(result) => {
                let peer = federation::storage::get_trusted_peer_by_domain(
                    db.as_ref(),
                    &result.peer_domain,
                )
                .await
                .ok()
                .flatten();

                Ok(PeerOperationResult {
                    success: true,
                    message: format!(
                        "Peer request approved. {} is now an active peer.",
                        result.peer_domain
                    ),
                    peer: peer.as_ref().map(TrustedPeerGql::from),
                })
            }
            Err(e) => Ok(PeerOperationResult {
                success: false,
                message: format!("Failed to approve peer request: {}", e),
                peer: None,
            }),
        }
    }

    /// Reject an incoming peer request.
    #[graphql(name = "rejectPeerRequest")]
    async fn reject_peer_request(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "ID of the peer request to reject")] request_id: String,
    ) -> Result<PeerOperationResult> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let request = federation::storage::get_peer_request(db.as_ref(), &request_id)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        match request {
            Some(req) if req.status == "pending_approval" => {
                federation::storage::update_peer_request_status(
                    db.as_ref(),
                    &request_id,
                    "rejected",
                )
                .await
                .map_err(|e| Error::new(format!("Database error: {}", e)))?;

                Ok(PeerOperationResult {
                    success: true,
                    message: format!("Peer request from {} rejected", req.requesting_domain),
                    peer: None,
                })
            }
            Some(req) => Ok(PeerOperationResult {
                success: false,
                message: format!("Cannot reject request with status '{}'", req.status),
                peer: None,
            }),
            None => Ok(PeerOperationResult {
                success: false,
                message: format!("Peer request '{}' not found", request_id),
                peer: None,
            }),
        }
    }
}

/// Result of triggering a job
#[derive(SimpleObject)]
pub struct JobTriggerResult {
    pub success: bool,
    pub message: String,
    pub job_name: String,
}

/// Result of setting user 2FA requirement
#[derive(SimpleObject)]
pub struct User2FAResult {
    pub success: bool,
    pub message: String,
    pub username: String,
    pub requires_2fa: bool,
}

/// Custom queries for admin operations
#[derive(Default)]
pub struct AdminQuery;

#[Object]
impl AdminQuery {
    /// Get recent job executions with optional filtering
    async fn job_logs(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by job name")] job_name: Option<String>,
        #[graphql(desc = "Limit number of results", default = 100)] limit: i64,
        #[graphql(desc = "Only show failed jobs")] only_failures: Option<bool>,
    ) -> Result<Vec<JobLog>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        use crate::entities::job_execution::{Column, Entity};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

        let mut query = Entity::find();

        // Filter by job name if provided
        if let Some(name) = job_name {
            query = query.filter(Column::JobName.eq(name));
        }

        // Filter by failures if requested
        if let Some(true) = only_failures {
            query = query.filter(Column::Success.eq(0));
        }

        // Order by most recent first and limit
        let results = query
            .order_by_desc(Column::StartedAt)
            .limit(limit as u64)
            .all(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        Ok(results
            .into_iter()
            .map(|model| JobLog {
                id: model.id,
                job_name: model.job_name,
                started_at: model.started_at,
                completed_at: model.completed_at,
                success: model.success,
                error_message: model.error_message,
                records_processed: model.records_processed,
            })
            .collect())
    }

    /// Get list of available jobs that can be triggered
    async fn available_jobs(&self) -> Result<Vec<JobInfo>> {
        Ok(vec![
            JobInfo {
                name: "cleanup_expired_sessions".to_string(),
                description: "Clean up expired user sessions".to_string(),
                schedule: "Hourly at :00".to_string(),
            },
            JobInfo {
                name: "cleanup_expired_refresh_tokens".to_string(),
                description: "Clean up expired refresh tokens".to_string(),
                schedule: "Hourly at :30".to_string(),
            },
            JobInfo {
                name: "cleanup_expired_challenges".to_string(),
                description: "Clean up expired WebAuthn challenges".to_string(),
                schedule: "Every 5 minutes".to_string(),
            },
            JobInfo {
                name: "cleanup_expired_device_codes".to_string(),
                description: "Clean up expired device authorization codes".to_string(),
                schedule: "Hourly at :45".to_string(),
            },
            JobInfo {
                name: "cleanup_expired_federation_requests".to_string(),
                description: "Clean up expired federation auth requests".to_string(),
                schedule: "Every 5 minutes".to_string(),
            },
            JobInfo {
                name: "refresh_peer_discovery".to_string(),
                description: "Re-verify active trusted peers and refresh discovery endpoints"
                    .to_string(),
                schedule: "Daily at 03:00".to_string(),
            },
        ])
    }

    /// List all trusted federation peers
    #[graphql(name = "trustedPeers")]
    async fn trusted_peers(&self, ctx: &Context<'_>) -> Result<Vec<TrustedPeerGql>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peers = federation::storage::list_trusted_peers(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        Ok(peers.iter().map(TrustedPeerGql::from).collect())
    }

    /// Get a single trusted peer by domain
    #[graphql(name = "trustedPeer")]
    async fn trusted_peer(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Domain of the peer")] domain: String,
    ) -> Result<Option<TrustedPeerGql>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let peer = federation::storage::get_trusted_peer_by_domain(db.as_ref(), &domain)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        Ok(peer.as_ref().map(TrustedPeerGql::from))
    }

    /// List federated identities for a user
    #[graphql(name = "federatedIdentities")]
    async fn federated_identities(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Username to query")] username: String,
    ) -> Result<Vec<FederatedIdentityGql>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        // Look up user by username to get their subject/ID
        let user = storage::get_user_by_username(db.as_ref(), &username)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new(format!("User '{}' not found", username)))?;

        let identities =
            federation::storage::list_federated_identities_for_user(db.as_ref(), &user.subject)
                .await
                .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        // For each identity, look up the peer domain from peer_id
        let mut results = Vec::with_capacity(identities.len());
        for ident in &identities {
            let peer_domain = match federation::storage::get_trusted_peer_by_id(
                db.as_ref(),
                &ident.peer_id,
            )
            .await
            {
                Ok(Some(p)) => p.domain,
                _ => ident.peer_id.clone(), // fallback to peer_id if lookup fails
            };

            results.push(FederatedIdentityGql {
                id: ident.id.clone(),
                local_user_id: ident.local_user_id.clone(),
                peer_domain,
                external_subject: ident.external_subject.clone(),
                external_issuer: ident.external_issuer.clone(),
                external_email: ident.external_email.clone(),
                linked_at: ident.linked_at.clone(),
                last_login_at: ident.last_login_at.clone(),
            });
        }

        Ok(results)
    }

    /// List incoming peer requests that are pending approval
    #[graphql(name = "pendingPeerRequests")]
    async fn pending_peer_requests(&self, ctx: &Context<'_>) -> Result<Vec<PeerRequestGql>> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        let requests = federation::storage::list_pending_peer_requests(db.as_ref())
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?;

        Ok(requests.iter().map(PeerRequestGql::from).collect())
    }

    /// Get 2FA status for a user
    async fn user_2fa_status(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Username to query")] username: String,
    ) -> Result<User2FAStatus> {
        let db = ctx
            .data::<Arc<DatabaseConnection>>()
            .map_err(|_| Error::new("Database connection not available"))?;

        // Get user by username
        let user = storage::get_user_by_username(db.as_ref(), &username)
            .await
            .map_err(|e| Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| Error::new(format!("User '{}' not found", username)))?;

        // Get user's passkeys count
        let passkeys = storage::get_passkeys_by_subject(db.as_ref(), &user.subject)
            .await
            .map_err(|e| Error::new(format!("Failed to get passkeys: {}", e)))?;

        Ok(User2FAStatus {
            username,
            subject: user.subject,
            requires_2fa: user.requires_2fa == 1,
            passkey_enrolled: user.passkey_enrolled_at.is_some(),
            passkey_count: passkeys.len() as i32,
            passkey_enrolled_at: user.passkey_enrolled_at,
        })
    }
}

/// Job log entry
#[derive(SimpleObject)]
pub struct JobLog {
    pub id: i64,
    pub job_name: String,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub success: Option<i64>,
    pub error_message: Option<String>,
    pub records_processed: Option<i64>,
}

/// Information about an available job
#[derive(SimpleObject)]
pub struct JobInfo {
    pub name: String,
    pub description: String,
    pub schedule: String,
}

/// User 2FA status information
#[derive(SimpleObject)]
pub struct User2FAStatus {
    pub username: String,
    pub subject: String,
    pub requires_2fa: bool,
    pub passkey_enrolled: bool,
    pub passkey_count: i32,
    pub passkey_enrolled_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Federation GraphQL types
// ---------------------------------------------------------------------------

#[derive(SimpleObject, Clone)]
pub struct TrustedPeerGql {
    pub domain: String,
    pub issuer_url: String,
    pub status: String,
    pub verification_level: Option<String>,
    pub verified_at: Option<String>,
    pub webfinger_issuer_match: Option<bool>,
    pub mapping_policy: String,
    pub trust_peer_acr: bool,
    pub jwks_pin_mode: String,
    pub scopes: String,
    pub last_discovery_refresh: Option<String>,
    pub last_discovery_error: Option<String>,
    pub created_at: String,
}

#[derive(SimpleObject)]
pub struct FederatedIdentityGql {
    pub id: String,
    pub local_user_id: String,
    pub peer_domain: String,
    pub external_subject: String,
    pub external_issuer: String,
    pub external_email: Option<String>,
    pub linked_at: String,
    pub last_login_at: Option<String>,
}

#[derive(SimpleObject)]
pub struct PeerOperationResult {
    pub success: bool,
    pub message: String,
    pub peer: Option<TrustedPeerGql>,
}

#[derive(SimpleObject, Clone)]
pub struct PeerRequestGql {
    pub id: String,
    pub requesting_issuer: String,
    pub requesting_domain: String,
    pub client_id_at_us: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

impl From<&federation::storage::PeerRequest> for PeerRequestGql {
    fn from(r: &federation::storage::PeerRequest) -> Self {
        Self {
            id: r.id.clone(),
            requesting_issuer: r.requesting_issuer.clone(),
            requesting_domain: r.requesting_domain.clone(),
            client_id_at_us: r.client_id_at_us.clone(),
            status: r.status.clone(),
            created_at: r.created_at.clone(),
            expires_at: r.expires_at.clone(),
        }
    }
}

impl From<&federation::storage::TrustedPeer> for TrustedPeerGql {
    fn from(p: &federation::storage::TrustedPeer) -> Self {
        Self {
            domain: p.domain.clone(),
            issuer_url: p.issuer_url.clone(),
            status: p.status.clone(),
            verification_level: p.verification_level.clone(),
            verified_at: p.verified_at.clone(),
            webfinger_issuer_match: p.webfinger_issuer_match,
            mapping_policy: p.mapping_policy.clone(),
            trust_peer_acr: p.trust_peer_acr,
            jwks_pin_mode: p.jwks_pin_mode.clone(),
            scopes: p.scopes.clone(),
            last_discovery_refresh: p.last_discovery_refresh.clone(),
            last_discovery_error: p.last_discovery_error.clone(),
            created_at: p.created_at.clone(),
        }
    }
}
