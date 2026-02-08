use std::collections::HashSet;

use serde_json::Value;

use crate::authz::condition;
use crate::authz::errors::AuthzError;
use crate::authz::AuthzState;

const MAX_DEPTH: usize = 10;

/// Check if `principal` (e.g. "user/alice") has `permission` (e.g. "vm:start")
/// on `resource` (e.g. "vm/vm-123"), given optional ABAC `context`.
pub fn check(
    state: &AuthzState,
    principal: &str,
    permission: &str,
    resource: &str,
    context: &Value,
) -> Result<bool, AuthzError> {
    // 1. Parse the resource ref
    let (resource_type, resource_id) = resource.split_once('/').ok_or_else(|| {
        AuthzError::InvalidPolicy(format!(
            "invalid resource reference `{resource}` (expected \"type/id\")"
        ))
    })?;

    // 2. Check ABAC rules first
    if check_abac_rules(state, principal, permission, context)? {
        return Ok(true);
    }

    // 3. Find which roles/relations grant this permission
    let granting_roles = match state.permission_roles.get(permission) {
        Some(roles) => roles.clone(),
        None => return Ok(false),
    };

    // 4. For each granting role, check if principal holds that role on the resource
    let mut visited = HashSet::new();
    for role in &granting_roles {
        if has_relation(
            state,
            principal,
            resource_type,
            resource_id,
            role,
            &mut visited,
            0,
        )? {
            return Ok(true);
        }
    }

    // 5. Also check direct relations that match the permission name
    // e.g. permission "start" might be granted by relation "owner" on the resource
    if let Some(res_def) = state.resources.get(resource_type) {
        for relation in &res_def.relations {
            // A relation directly grants its name as a pseudo-permission
            let qualified = format!("{resource_type}:{relation}");
            if qualified == permission || *relation == permission {
                visited.clear();
                if has_relation(
                    state,
                    principal,
                    resource_type,
                    resource_id,
                    relation,
                    &mut visited,
                    0,
                )? {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Check ABAC rules that match the permission and principal.
fn check_abac_rules(
    state: &AuthzState,
    principal: &str,
    permission: &str,
    context: &Value,
) -> Result<bool, AuthzError> {
    for rule in &state.rules {
        // Check if this rule applies to the requested permission
        if !rule.permissions.contains(&permission.to_string()) {
            continue;
        }

        // Check if the principal matches any of the rule's principal patterns
        let principal_match = rule.principals.is_empty()
            || rule.principals.iter().any(|p| matches_principal(principal, p, state));

        if !principal_match {
            continue;
        }

        // Evaluate condition if present
        if let Some(cond_str) = &rule.condition {
            let expr = condition::parse_condition(cond_str)?;
            let result = condition::evaluate(&expr, context)?;
            if result && rule.effect == "allow" {
                return Ok(true);
            }
        } else if rule.effect == "allow" {
            // No condition, rule applies unconditionally
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a principal matches a principal pattern.
/// Patterns: "group:finance" matches if principal is a member of group/finance.
fn matches_principal(principal: &str, pattern: &str, state: &AuthzState) -> bool {
    // Direct match: pattern = "user/alice", principal = "user/alice"
    if principal == pattern {
        return true;
    }

    // Group pattern: "group:groupname" -> check if principal has "member" on "group/groupname"
    if let Some(group_name) = pattern.strip_prefix("group:") {
        let subjects = state.tuples.subjects_for("group", group_name, "member");
        return subjects.iter().any(|s| s.as_direct() == principal);
    }

    false
}

/// Recursively check if principal holds the given relation on the object,
/// following userset references.
fn has_relation(
    state: &AuthzState,
    principal: &str,
    object_type: &str,
    object_id: &str,
    relation: &str,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<bool, AuthzError> {
    if depth >= MAX_DEPTH {
        return Ok(false);
    }

    let key = format!("{object_type}/{object_id}#{relation}@{depth}");
    if visited.contains(&key) {
        return Ok(false);
    }
    visited.insert(key);

    let subjects = state.tuples.subjects_for(object_type, object_id, relation);

    for subject in subjects {
        // Direct match
        if subject.relation.is_none() && subject.as_direct() == principal {
            return Ok(true);
        }

        // Userset: subject is "type/id#relation" -> check if principal has that relation
        if let Some(sub_relation) = &subject.relation {
            if has_relation(
                state,
                principal,
                &subject.subject_type,
                &subject.subject_id,
                sub_relation,
                visited,
                depth + 1,
            )? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Expand: list all subjects that have the given permission on the resource.
pub fn expand(
    state: &AuthzState,
    permission: &str,
    resource: &str,
) -> Result<Vec<String>, AuthzError> {
    let (resource_type, resource_id) = resource.split_once('/').ok_or_else(|| {
        AuthzError::InvalidPolicy(format!(
            "invalid resource reference `{resource}` (expected \"type/id\")"
        ))
    })?;

    let mut result = HashSet::new();

    // Find which roles grant this permission
    if let Some(granting_roles) = state.permission_roles.get(permission) {
        for role in granting_roles {
            collect_subjects(
                state,
                resource_type,
                resource_id,
                role,
                &mut result,
                &mut HashSet::new(),
                0,
            )?;
        }
    }

    let mut subjects: Vec<String> = result.into_iter().collect();
    subjects.sort();
    Ok(subjects)
}

/// Recursively collect all direct subjects reachable via a relation on an object.
fn collect_subjects(
    state: &AuthzState,
    object_type: &str,
    object_id: &str,
    relation: &str,
    result: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<(), AuthzError> {
    if depth >= MAX_DEPTH {
        return Ok(());
    }

    let key = format!("{object_type}/{object_id}#{relation}");
    if visited.contains(&key) {
        return Ok(());
    }
    visited.insert(key);

    let subjects = state.tuples.subjects_for(object_type, object_id, relation);

    for subject in subjects {
        if subject.relation.is_none() {
            result.insert(subject.as_direct());
        } else if let Some(sub_relation) = &subject.relation {
            // Expand userset
            collect_subjects(
                state,
                &subject.subject_type,
                &subject.subject_id,
                sub_relation,
                result,
                visited,
                depth + 1,
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::loader::compile_policies;
    use crate::authz::types::*;
    use serde_json::json;

    fn make_vm_state() -> AuthzState {
        let parsed = ParsedPolicy {
            resources: vec![ResourceDefinition {
                resource_type: "vm".into(),
                relations: vec!["owner".into()],
                permissions: vec!["start".into(), "stop".into(), "view_console".into()],
            }],
            roles: vec![
                RoleDef {
                    name: "vm_viewer".into(),
                    permissions: vec!["vm:view_console".into()],
                    includes: vec![],
                },
                RoleDef {
                    name: "vm_admin".into(),
                    permissions: vec!["vm:start".into(), "vm:stop".into()],
                    includes: vec!["vm_viewer".into()],
                },
            ],
            rules: vec![],
            grants: vec![
                GrantTuple {
                    relation: "vm_admin".into(),
                    object_type: "vm".into(),
                    object_id: "vm-123".into(),
                    subject_type: "user".into(),
                    subject_id: "alice".into(),
                    subject_relation: None,
                },
                GrantTuple {
                    relation: "vm_viewer".into(),
                    object_type: "vm".into(),
                    object_id: "vm-456".into(),
                    subject_type: "group".into(),
                    subject_id: "engineers".into(),
                    subject_relation: Some("member".into()),
                },
                GrantTuple {
                    relation: "member".into(),
                    object_type: "group".into(),
                    object_id: "engineers".into(),
                    subject_type: "user".into(),
                    subject_id: "bob".into(),
                    subject_relation: None,
                },
            ],
        };
        compile_policies(vec![parsed]).unwrap()
    }

    #[test]
    fn test_check_direct_grant() {
        let state = make_vm_state();
        // alice has vm_admin on vm/vm-123, which grants vm:start
        assert!(check(&state, "user/alice", "vm:start", "vm/vm-123", &json!({})).unwrap());
        assert!(check(&state, "user/alice", "vm:stop", "vm/vm-123", &json!({})).unwrap());
    }

    #[test]
    fn test_check_inherited_permission() {
        let state = make_vm_state();
        // alice has vm_admin which includes vm_viewer -> vm:view_console
        assert!(
            check(&state, "user/alice", "vm:view_console", "vm/vm-123", &json!({})).unwrap()
        );
    }

    #[test]
    fn test_check_no_permission() {
        let state = make_vm_state();
        // alice has no grant on vm-456
        assert!(!check(&state, "user/alice", "vm:start", "vm/vm-456", &json!({})).unwrap());
        // bob has no grant on vm-123
        assert!(!check(&state, "user/bob", "vm:start", "vm/vm-123", &json!({})).unwrap());
    }

    #[test]
    fn test_check_userset_membership() {
        let state = make_vm_state();
        // bob is member of group/engineers, which has vm_viewer on vm/vm-456
        assert!(
            check(&state, "user/bob", "vm:view_console", "vm/vm-456", &json!({})).unwrap()
        );
        // but bob can't start vm-456 (only viewer)
        assert!(!check(&state, "user/bob", "vm:start", "vm/vm-456", &json!({})).unwrap());
    }

    #[test]
    fn test_check_unknown_permission() {
        let state = make_vm_state();
        assert!(
            !check(&state, "user/alice", "vm:delete", "vm/vm-123", &json!({})).unwrap()
        );
    }

    #[test]
    fn test_expand_direct() {
        let state = make_vm_state();
        let subjects = expand(&state, "vm:start", "vm/vm-123").unwrap();
        assert_eq!(subjects, vec!["user/alice"]);
    }

    #[test]
    fn test_expand_userset() {
        let state = make_vm_state();
        let subjects = expand(&state, "vm:view_console", "vm/vm-456").unwrap();
        assert_eq!(subjects, vec!["user/bob"]);
    }

    #[test]
    fn test_check_abac_rule() {
        let parsed = ParsedPolicy {
            resources: vec![ResourceDefinition {
                resource_type: "invoice".into(),
                relations: vec![],
                permissions: vec!["view".into()],
            }],
            roles: vec![],
            rules: vec![PolicyRule {
                name: "AllowFinanceDuringHours".into(),
                effect: "allow".into(),
                permissions: vec!["invoice:view".into()],
                principals: vec!["group:finance".into()],
                condition: Some(
                    "request.time.hour >= 9 && request.time.hour < 17".into(),
                ),
            }],
            grants: vec![
                GrantTuple {
                    relation: "member".into(),
                    object_type: "group".into(),
                    object_id: "finance".into(),
                    subject_type: "user".into(),
                    subject_id: "carol".into(),
                    subject_relation: None,
                },
            ],
        };
        let state = compile_policies(vec![parsed]).unwrap();

        // Carol is in finance, during business hours -> allowed
        let ctx = json!({ "request": { "time": { "hour": 14 } } });
        assert!(check(&state, "user/carol", "invoice:view", "invoice/inv-1", &ctx).unwrap());

        // Carol is in finance, outside business hours -> denied
        let ctx_late = json!({ "request": { "time": { "hour": 22 } } });
        assert!(
            !check(&state, "user/carol", "invoice:view", "invoice/inv-1", &ctx_late).unwrap()
        );

        // Dave is NOT in finance -> denied even during business hours
        let ctx_hours = json!({ "request": { "time": { "hour": 14 } } });
        assert!(
            !check(&state, "user/dave", "invoice:view", "invoice/inv-1", &ctx_hours).unwrap()
        );
    }

    #[test]
    fn test_max_depth_prevents_infinite_loop() {
        // Create a deep chain of userset references
        let mut grants = Vec::new();
        for i in 0..15 {
            grants.push(GrantTuple {
                relation: "member".into(),
                object_type: "group".into(),
                object_id: format!("g{i}"),
                subject_type: "group".into(),
                subject_id: format!("g{}", i + 1),
                subject_relation: Some("member".into()),
            });
        }
        // The actual user at the end
        grants.push(GrantTuple {
            relation: "member".into(),
            object_type: "group".into(),
            object_id: "g15".into(),
            subject_type: "user".into(),
            subject_id: "deep".into(),
            subject_relation: None,
        });
        // Role that grants via the first group
        grants.push(GrantTuple {
            relation: "viewer".into(),
            object_type: "res".into(),
            object_id: "r1".into(),
            subject_type: "group".into(),
            subject_id: "g0".into(),
            subject_relation: Some("member".into()),
        });

        let parsed = ParsedPolicy {
            roles: vec![RoleDef {
                name: "viewer".into(),
                permissions: vec!["res:view".into()],
                includes: vec![],
            }],
            grants,
            ..Default::default()
        };
        let state = compile_policies(vec![parsed]).unwrap();

        // The chain is 16 levels deep, max depth is 10, so this should return false
        assert!(!check(&state, "user/deep", "res:view", "res/r1", &json!({})).unwrap());
    }
}
