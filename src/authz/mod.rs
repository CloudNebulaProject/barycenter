pub mod condition;
pub mod engine;
pub mod errors;
pub mod loader;
pub mod policy;
pub mod types;
pub mod web;

use std::collections::HashMap;
use types::{PolicyRule, ResourceDefinition, RoleDef, TupleIndex};

/// Fully compiled authorization state, loaded from KDL policy files.
/// Immutable after construction — configuration changes require a service reload.
#[derive(Debug)]
pub struct AuthzState {
    /// resource_type -> ResourceDefinition
    pub resources: HashMap<String, ResourceDefinition>,
    /// role_name -> RoleDef (permissions + includes)
    pub roles: HashMap<String, RoleDef>,
    /// ABAC rules
    pub rules: Vec<PolicyRule>,
    /// All relationship tuples, indexed for fast lookup
    pub tuples: TupleIndex,
    /// permission -> list of role names that grant it (pre-computed, includes inheritance)
    pub permission_roles: HashMap<String, Vec<String>>,
}
