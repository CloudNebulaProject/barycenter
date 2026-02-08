use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::authz::errors::AuthzError;
use crate::authz::policy::parse_kdl_document;
use crate::authz::types::*;
use crate::authz::AuthzState;

/// Load all `.kdl` policy files from the given directory and compile them
/// into a single immutable `AuthzState`.
pub fn load_policies(dir: &Path) -> Result<AuthzState, AuthzError> {
    if !dir.is_dir() {
        return Err(AuthzError::InvalidPolicy(format!(
            "policies directory `{}` does not exist or is not a directory",
            dir.display()
        )));
    }

    let mut all_parsed = Vec::new();
    let mut file_count = 0;

    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "kdl")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let contents =
            std::fs::read_to_string(&path).map_err(|source| AuthzError::PolicyLoadError {
                path: path.display().to_string(),
                source,
            })?;
        let parsed = parse_kdl_document(&contents)?;
        all_parsed.push(parsed);
        file_count += 1;
    }

    let state = compile_policies(all_parsed)?;

    tracing::info!(
        files = file_count,
        resources = state.resources.len(),
        roles = state.roles.len(),
        rules = state.rules.len(),
        tuples = state.tuples.tuple_count(),
        "Loaded authorization policies"
    );

    Ok(state)
}

/// Merge and compile all parsed policies into a single `AuthzState`.
pub fn compile_policies(parsed: Vec<ParsedPolicy>) -> Result<AuthzState, AuthzError> {
    let mut resources: HashMap<String, ResourceDefinition> = HashMap::new();
    let mut roles: HashMap<String, RoleDef> = HashMap::new();
    let mut rules: Vec<PolicyRule> = Vec::new();
    let mut grants: Vec<GrantTuple> = Vec::new();

    // Merge all parsed policies
    for p in parsed {
        for res in p.resources {
            resources.insert(res.resource_type.clone(), res);
        }
        for role in p.roles {
            roles.insert(role.name.clone(), role);
        }
        rules.extend(p.rules);
        grants.extend(p.grants);
    }

    // Validate role inheritance: no cycles (topological sort)
    check_role_cycles(&roles)?;

    // Pre-validate condition expressions parse correctly
    for rule in &rules {
        if let Some(cond) = &rule.condition {
            crate::authz::condition::parse_condition(cond)?;
        }
    }

    // Build permission_roles: permission -> list of role names that grant it
    let permission_roles = build_permission_roles(&roles);

    // Build TupleIndex from grants
    let mut tuples = TupleIndex::new();
    for g in &grants {
        let obj = ObjectRef {
            object_type: g.object_type.clone(),
            object_id: g.object_id.clone(),
        };
        let subj = SubjectRef {
            subject_type: g.subject_type.clone(),
            subject_id: g.subject_id.clone(),
            relation: g.subject_relation.clone(),
        };
        tuples.insert(&obj, &g.relation, &subj);
    }

    Ok(AuthzState {
        resources,
        roles,
        rules,
        tuples,
        permission_roles,
    })
}

/// Check for cycles in role inheritance using DFS.
fn check_role_cycles(roles: &HashMap<String, RoleDef>) -> Result<(), AuthzError> {
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();

    for name in roles.keys() {
        if !visited.contains(name) {
            dfs_cycle_check(name, roles, &mut visited, &mut in_stack)?;
        }
    }
    Ok(())
}

fn dfs_cycle_check(
    name: &str,
    roles: &HashMap<String, RoleDef>,
    visited: &mut HashSet<String>,
    in_stack: &mut HashSet<String>,
) -> Result<(), AuthzError> {
    visited.insert(name.to_string());
    in_stack.insert(name.to_string());

    if let Some(role) = roles.get(name) {
        for included in &role.includes {
            if in_stack.contains(included.as_str()) {
                return Err(AuthzError::CyclicRoleInheritance(format!(
                    "{name} -> {included}"
                )));
            }
            if !visited.contains(included.as_str()) {
                dfs_cycle_check(included, roles, visited, in_stack)?;
            }
        }
    }

    in_stack.remove(name);
    Ok(())
}

/// Build a map: fully-qualified permission -> list of role names that grant it
/// (expanding role inheritance).
fn build_permission_roles(roles: &HashMap<String, RoleDef>) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for (role_name, _) in roles {
        let perms = collect_role_permissions(role_name, roles, &mut HashSet::new());
        for perm in perms {
            map.entry(perm).or_default().push(role_name.clone());
        }
    }

    map
}

/// Recursively collect all permissions from a role, following includes.
fn collect_role_permissions(
    role_name: &str,
    roles: &HashMap<String, RoleDef>,
    visited: &mut HashSet<String>,
) -> Vec<String> {
    if visited.contains(role_name) {
        return Vec::new();
    }
    visited.insert(role_name.to_string());

    let Some(role) = roles.get(role_name) else {
        return Vec::new();
    };

    let mut perms: Vec<String> = role.permissions.clone();
    for included in &role.includes {
        perms.extend(collect_role_permissions(included, roles, visited));
    }

    perms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_parsed_vm() -> ParsedPolicy {
        ParsedPolicy {
            resources: vec![ResourceDefinition {
                resource_type: "vm".into(),
                relations: vec!["owner".into(), "viewer".into()],
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
            grants: vec![GrantTuple {
                relation: "vm_admin".into(),
                object_type: "vm".into(),
                object_id: "vm-123".into(),
                subject_type: "user".into(),
                subject_id: "alice".into(),
                subject_relation: None,
            }],
        }
    }

    #[test]
    fn test_compile_basic() {
        let state = compile_policies(vec![make_parsed_vm()]).unwrap();
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.roles.len(), 2);
        assert_eq!(state.tuples.tuple_count(), 1);
    }

    #[test]
    fn test_permission_roles_inheritance() {
        let state = compile_policies(vec![make_parsed_vm()]).unwrap();
        // vm_admin grants vm:start, vm:stop directly and vm:view_console via includes
        let start_roles = state.permission_roles.get("vm:start").unwrap();
        assert!(start_roles.contains(&"vm_admin".to_string()));

        let view_roles = state.permission_roles.get("vm:view_console").unwrap();
        assert!(view_roles.contains(&"vm_viewer".to_string()));
        assert!(view_roles.contains(&"vm_admin".to_string()));
    }

    #[test]
    fn test_cyclic_roles_detected() {
        let parsed = ParsedPolicy {
            roles: vec![
                RoleDef {
                    name: "a".into(),
                    permissions: vec![],
                    includes: vec!["b".into()],
                },
                RoleDef {
                    name: "b".into(),
                    permissions: vec![],
                    includes: vec!["a".into()],
                },
            ],
            ..Default::default()
        };
        let err = compile_policies(vec![parsed]).unwrap_err();
        assert!(matches!(err, AuthzError::CyclicRoleInheritance(_)));
    }

    #[test]
    fn test_merge_multiple_files() {
        let p1 = ParsedPolicy {
            resources: vec![ResourceDefinition {
                resource_type: "vm".into(),
                relations: vec![],
                permissions: vec!["start".into()],
            }],
            roles: vec![RoleDef {
                name: "vm_admin".into(),
                permissions: vec!["vm:start".into()],
                includes: vec![],
            }],
            grants: vec![GrantTuple {
                relation: "vm_admin".into(),
                object_type: "vm".into(),
                object_id: "vm-1".into(),
                subject_type: "user".into(),
                subject_id: "alice".into(),
                subject_relation: None,
            }],
            ..Default::default()
        };
        let p2 = ParsedPolicy {
            resources: vec![ResourceDefinition {
                resource_type: "invoice".into(),
                relations: vec![],
                permissions: vec!["view".into()],
            }],
            grants: vec![GrantTuple {
                relation: "viewer".into(),
                object_type: "invoice".into(),
                object_id: "inv-1".into(),
                subject_type: "user".into(),
                subject_id: "bob".into(),
                subject_relation: None,
            }],
            ..Default::default()
        };

        let state = compile_policies(vec![p1, p2]).unwrap();
        assert_eq!(state.resources.len(), 2);
        assert_eq!(state.tuples.tuple_count(), 2);
    }

    #[test]
    fn test_load_from_directory() {
        let dir = tempfile::tempdir().unwrap();

        // Write vm_policy.kdl
        std::fs::write(
            dir.path().join("vm_policy.kdl"),
            r#"
resource "vm" {
    relations {
        - "owner"
    }
    permissions {
        - "start"
        - "stop"
    }
}

role "vm_admin" {
    permissions {
        - "vm:start"
        - "vm:stop"
    }
}

grant "vm_admin" on="vm/vm-123" to="user/alice"
"#,
        )
        .unwrap();

        // Write invoice_policy.kdl
        std::fs::write(
            dir.path().join("invoice_policy.kdl"),
            r#"
resource "invoice" {
    permissions {
        - "view"
        - "pay"
    }
}

grant "member" on="group/finance" to="user/carol"
"#,
        )
        .unwrap();

        // Also write a non-KDL file that should be ignored
        std::fs::write(dir.path().join("README.md"), "not a policy").unwrap();

        let state = load_policies(dir.path()).unwrap();
        assert_eq!(state.resources.len(), 2);
        assert!(state.resources.contains_key("vm"));
        assert!(state.resources.contains_key("invoice"));
        assert_eq!(state.roles.len(), 1);
        assert_eq!(state.tuples.tuple_count(), 2);
    }

    #[test]
    fn test_load_nonexistent_directory() {
        let err = load_policies(Path::new("/nonexistent/path")).unwrap_err();
        assert!(matches!(err, AuthzError::InvalidPolicy(_)));
    }
}
