use crate::authz::errors::AuthzError;
use crate::authz::types::*;
use kdl::KdlDocument;

/// Parse a KDL document string into typed policy structs.
pub fn parse_kdl_document(source: &str) -> Result<ParsedPolicy, AuthzError> {
    let doc: KdlDocument = source
        .parse()
        .map_err(|e: kdl::KdlError| AuthzError::KdlParse(e.to_string()))?;

    let mut policy = ParsedPolicy::default();

    for node in doc.nodes() {
        match node.name().value() {
            "resource" => {
                let resource_type = first_string_arg(node).ok_or_else(|| {
                    AuthzError::InvalidPolicy(
                        "resource node requires a string argument (e.g. resource \"vm\")".into(),
                    )
                })?;

                let mut relations = Vec::new();
                let mut permissions = Vec::new();

                if let Some(children) = node.children() {
                    for child in children.nodes() {
                        match child.name().value() {
                            "relations" => {
                                relations = dash_list(child);
                            }
                            "permissions" => {
                                permissions = dash_list(child);
                            }
                            other => {
                                return Err(AuthzError::InvalidPolicy(format!(
                                    "unexpected child `{other}` in resource `{resource_type}` (expected `relations` or `permissions`)"
                                )));
                            }
                        }
                    }
                }

                policy.resources.push(ResourceDefinition {
                    resource_type,
                    relations,
                    permissions,
                });
            }
            "role" => {
                let name = first_string_arg(node).ok_or_else(|| {
                    AuthzError::InvalidPolicy(
                        "role node requires a string argument (e.g. role \"vm_admin\")".into(),
                    )
                })?;

                let mut permissions = Vec::new();
                let mut includes = Vec::new();

                if let Some(children) = node.children() {
                    for child in children.nodes() {
                        match child.name().value() {
                            "permissions" => {
                                permissions = dash_list(child);
                            }
                            "includes" => {
                                includes = dash_list(child);
                            }
                            other => {
                                return Err(AuthzError::InvalidPolicy(format!(
                                    "unexpected child `{other}` in role `{name}` (expected `permissions` or `includes`)"
                                )));
                            }
                        }
                    }
                }

                policy.roles.push(RoleDef {
                    name,
                    permissions,
                    includes,
                });
            }
            "rule" => {
                let name = first_string_arg(node).ok_or_else(|| {
                    AuthzError::InvalidPolicy(
                        "rule node requires a string argument (e.g. rule \"MyRule\" effect=\"allow\")"
                            .into(),
                    )
                })?;

                let effect = node
                    .get("effect")
                    .and_then(|v| v.as_string())
                    .unwrap_or("allow")
                    .to_string();

                let mut permissions = Vec::new();
                let mut principals = Vec::new();
                let mut condition = None;

                if let Some(children) = node.children() {
                    for child in children.nodes() {
                        match child.name().value() {
                            "permissions" => {
                                permissions = dash_list(child);
                            }
                            "principals" => {
                                principals = dash_list(child);
                            }
                            "condition" => {
                                condition = first_string_arg(child);
                            }
                            other => {
                                return Err(AuthzError::InvalidPolicy(format!(
                                    "unexpected child `{other}` in rule `{name}`"
                                )));
                            }
                        }
                    }
                }

                policy.rules.push(PolicyRule {
                    name,
                    effect,
                    permissions,
                    principals,
                    condition,
                });
            }
            "grant" => {
                let relation = first_string_arg(node).ok_or_else(|| {
                    AuthzError::InvalidGrant(
                        "grant node requires a relation argument (e.g. grant \"vm_admin\" on=\"vm/vm-123\" to=\"user/alice\")"
                            .into(),
                    )
                })?;

                let on = node
                    .get("on")
                    .and_then(|v| v.as_string())
                    .ok_or_else(|| {
                        AuthzError::InvalidGrant(format!(
                            "grant `{relation}` missing `on` property (e.g. on=\"vm/vm-123\")"
                        ))
                    })?;

                let to = node
                    .get("to")
                    .and_then(|v| v.as_string())
                    .ok_or_else(|| {
                        AuthzError::InvalidGrant(format!(
                            "grant `{relation}` missing `to` property (e.g. to=\"user/alice\")"
                        ))
                    })?;

                let obj = ObjectRef::parse(on).ok_or_else(|| {
                    AuthzError::InvalidGrant(format!(
                        "invalid object reference `{on}` in grant `{relation}` (expected \"type/id\")"
                    ))
                })?;

                let subj = SubjectRef::parse(to).ok_or_else(|| {
                    AuthzError::InvalidGrant(format!(
                        "invalid subject reference `{to}` in grant `{relation}` (expected \"type/id\" or \"type/id#relation\")"
                    ))
                })?;

                policy.grants.push(GrantTuple {
                    relation,
                    object_type: obj.object_type,
                    object_id: obj.object_id,
                    subject_type: subj.subject_type,
                    subject_id: subj.subject_id,
                    subject_relation: subj.relation,
                });
            }
            other => {
                // Ignore comments and unknown top-level nodes with a warning
                tracing::warn!("ignoring unknown top-level KDL node `{other}`");
            }
        }
    }

    Ok(policy)
}

/// Extract the first string argument from a KDL node.
fn first_string_arg(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Extract dash-list children: nodes named "-" whose first argument is a string.
/// Example KDL:
/// ```kdl
/// permissions {
///     - "start"
///     - "stop"
/// }
/// ```
fn dash_list(node: &kdl::KdlNode) -> Vec<String> {
    let Some(children) = node.children() else {
        return Vec::new();
    };
    children
        .nodes()
        .iter()
        .filter(|n| n.name().value() == "-")
        .filter_map(|n| first_string_arg(n))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resource() {
        let kdl = r#"
resource "vm" {
    relations {
        - "owner"
        - "viewer"
    }
    permissions {
        - "start"
        - "stop"
        - "view_console"
    }
}
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.resources.len(), 1);
        let res = &policy.resources[0];
        assert_eq!(res.resource_type, "vm");
        assert_eq!(res.relations, vec!["owner", "viewer"]);
        assert_eq!(res.permissions, vec!["start", "stop", "view_console"]);
    }

    #[test]
    fn test_parse_role_with_includes() {
        let kdl = r#"
role "vm_viewer" {
    permissions {
        - "vm:view_console"
    }
}

role "vm_admin" {
    includes {
        - "vm_viewer"
    }
    permissions {
        - "vm:start"
        - "vm:stop"
    }
}
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.roles.len(), 2);

        let admin = &policy.roles[1];
        assert_eq!(admin.name, "vm_admin");
        assert_eq!(admin.includes, vec!["vm_viewer"]);
        assert_eq!(admin.permissions, vec!["vm:start", "vm:stop"]);
    }

    #[test]
    fn test_parse_rule_with_condition() {
        let kdl = r#"
rule "AllowFinanceViewDuringBusinessHours" effect="allow" {
    permissions {
        - "invoice:view"
    }
    principals {
        - "group:finance"
    }
    condition "request.time.hour >= 9 && request.time.hour < 17"
}
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.rules.len(), 1);
        let rule = &policy.rules[0];
        assert_eq!(rule.name, "AllowFinanceViewDuringBusinessHours");
        assert_eq!(rule.effect, "allow");
        assert_eq!(rule.permissions, vec!["invoice:view"]);
        assert_eq!(rule.principals, vec!["group:finance"]);
        assert_eq!(
            rule.condition.as_deref(),
            Some("request.time.hour >= 9 && request.time.hour < 17")
        );
    }

    #[test]
    fn test_parse_grant_direct() {
        let kdl = r#"
grant "vm_admin" on="vm/vm-123" to="user/alice"
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.grants.len(), 1);
        let g = &policy.grants[0];
        assert_eq!(g.relation, "vm_admin");
        assert_eq!(g.object_type, "vm");
        assert_eq!(g.object_id, "vm-123");
        assert_eq!(g.subject_type, "user");
        assert_eq!(g.subject_id, "alice");
        assert!(g.subject_relation.is_none());
    }

    #[test]
    fn test_parse_grant_userset() {
        let kdl = r#"
grant "vm_viewer" on="vm/vm-456" to="group/engineers#member"
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.grants.len(), 1);
        let g = &policy.grants[0];
        assert_eq!(g.relation, "vm_viewer");
        assert_eq!(g.subject_type, "group");
        assert_eq!(g.subject_id, "engineers");
        assert_eq!(g.subject_relation.as_deref(), Some("member"));
    }

    #[test]
    fn test_parse_full_vm_policy() {
        let kdl = r#"
resource "vm" {
    relations {
        - "owner"
        - "viewer"
    }
    permissions {
        - "start"
        - "stop"
        - "view_console"
    }
}

role "vm_viewer" {
    permissions {
        - "vm:view_console"
    }
}

role "vm_admin" {
    includes {
        - "vm_viewer"
    }
    permissions {
        - "vm:start"
        - "vm:stop"
    }
}

grant "vm_admin" on="vm/vm-123" to="user/alice"
grant "vm_viewer" on="vm/vm-456" to="group/engineers#member"
"#;
        let policy = parse_kdl_document(kdl).unwrap();
        assert_eq!(policy.resources.len(), 1);
        assert_eq!(policy.roles.len(), 2);
        assert_eq!(policy.grants.len(), 2);
    }

    #[test]
    fn test_parse_missing_grant_on() {
        let kdl = r#"grant "admin" to="user/alice""#;
        let err = parse_kdl_document(kdl).unwrap_err();
        assert!(matches!(err, AuthzError::InvalidGrant(_)));
    }

    #[test]
    fn test_parse_missing_grant_to() {
        let kdl = r#"grant "admin" on="vm/vm-1""#;
        let err = parse_kdl_document(kdl).unwrap_err();
        assert!(matches!(err, AuthzError::InvalidGrant(_)));
    }
}
