//! Barycenter - OpenID Connect Identity Provider
//!
//! This library provides the core functionality for the Barycenter OpenID Connect IdP.
//! It exposes all modules for testing purposes.

pub mod admin_graphql;
pub mod admin_mutations;
pub mod authz;
pub mod entities;
pub mod errors;
pub mod jobs;
pub mod jwks;
pub mod session;
pub mod settings;
pub mod storage;
pub mod user_sync;
pub mod web;
pub mod webauthn_manager;
