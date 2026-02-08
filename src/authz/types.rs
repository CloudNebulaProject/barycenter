use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reference to an object: "type/id" e.g. "vm/vm-123"
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectRef {
    pub object_type: String,
    pub object_id: String,
}

impl ObjectRef {
    pub fn parse(s: &str) -> Option<Self> {
        let (t, id) = s.split_once('/')?;
        if t.is_empty() || id.is_empty() {
            return None;
        }
        Some(Self {
            object_type: t.to_string(),
            object_id: id.to_string(),
        })
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.object_type, self.object_id)
    }
}

/// Reference to a subject: "type/id" or "type/id#relation" for usersets
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectRef {
    pub subject_type: String,
    pub subject_id: String,
    /// Optional relation for userset references like "group/engineers#member"
    pub relation: Option<String>,
}

impl SubjectRef {
    pub fn parse(s: &str) -> Option<Self> {
        // Try "type/id#relation" first
        if let Some((type_id, relation)) = s.split_once('#') {
            let (t, id) = type_id.split_once('/')?;
            if t.is_empty() || id.is_empty() || relation.is_empty() {
                return None;
            }
            Some(Self {
                subject_type: t.to_string(),
                subject_id: id.to_string(),
                relation: Some(relation.to_string()),
            })
        } else {
            let (t, id) = s.split_once('/')?;
            if t.is_empty() || id.is_empty() {
                return None;
            }
            Some(Self {
                subject_type: t.to_string(),
                subject_id: id.to_string(),
                relation: None,
            })
        }
    }

    /// Returns "type/id" without the relation part.
    pub fn as_direct(&self) -> String {
        format!("{}/{}", self.subject_type, self.subject_id)
    }
}

impl std::fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.subject_type, self.subject_id)?;
        if let Some(rel) = &self.relation {
            write!(f, "#{}", rel)?;
        }
        Ok(())
    }
}

/// Indexed collection of relationship tuples for fast lookup.
#[derive(Debug, Clone, Default)]
pub struct TupleIndex {
    /// (object_type, object_id, relation) -> list of subjects
    by_object: HashMap<(String, String, String), Vec<SubjectRef>>,
    /// (subject_type, subject_id) -> list of (object, relation)
    by_subject: HashMap<(String, String), Vec<(ObjectRef, String)>>,
}

impl TupleIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, object: &ObjectRef, relation: &str, subject: &SubjectRef) {
        self.by_object
            .entry((
                object.object_type.clone(),
                object.object_id.clone(),
                relation.to_string(),
            ))
            .or_default()
            .push(subject.clone());

        self.by_subject
            .entry((subject.subject_type.clone(), subject.subject_id.clone()))
            .or_default()
            .push((object.clone(), relation.to_string()));
    }

    /// Get all subjects that have `relation` on the given object.
    pub fn subjects_for(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
    ) -> &[SubjectRef] {
        self.by_object
            .get(&(
                object_type.to_string(),
                object_id.to_string(),
                relation.to_string(),
            ))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all (object, relation) pairs where the given subject appears.
    pub fn objects_for(&self, subject_type: &str, subject_id: &str) -> &[(ObjectRef, String)] {
        self.by_subject
            .get(&(subject_type.to_string(), subject_id.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn tuple_count(&self) -> usize {
        self.by_object.values().map(|v| v.len()).sum()
    }
}

// ---------- API request/response types ----------

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    /// e.g. "user/alice"
    pub principal: String,
    /// e.g. "vm:start"
    pub permission: String,
    /// e.g. "vm/vm-123"
    pub resource: String,
    /// Optional context for ABAC condition evaluation
    #[serde(default)]
    pub context: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub allowed: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExpandRequest {
    /// e.g. "vm:start"
    pub permission: String,
    /// e.g. "vm/vm-123"
    pub resource: String,
}

#[derive(Debug, Serialize)]
pub struct ExpandResponse {
    pub subjects: Vec<String>,
}

// ---------- Policy domain types ----------

#[derive(Debug, Clone)]
pub struct ResourceDefinition {
    pub resource_type: String,
    pub relations: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RoleDef {
    pub name: String,
    /// Fully-qualified permissions like "vm:start"
    pub permissions: Vec<String>,
    /// Other role names this role includes (inherits from)
    pub includes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    /// "allow" or "deny"
    pub effect: String,
    /// Fully-qualified permissions like "invoice:view"
    pub permissions: Vec<String>,
    /// Principal patterns like "group:finance"
    pub principals: Vec<String>,
    /// Optional condition expression (raw string, compiled on load)
    pub condition: Option<String>,
}

/// A single relationship tuple parsed from a `grant` KDL node.
#[derive(Debug, Clone)]
pub struct GrantTuple {
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub subject_type: String,
    pub subject_id: String,
    /// Optional relation on the subject for userset references
    pub subject_relation: Option<String>,
}

/// Intermediate result from parsing a single KDL file.
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub resources: Vec<ResourceDefinition>,
    pub roles: Vec<RoleDef>,
    pub rules: Vec<PolicyRule>,
    pub grants: Vec<GrantTuple>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_ref_parse() {
        let r = ObjectRef::parse("vm/vm-123").unwrap();
        assert_eq!(r.object_type, "vm");
        assert_eq!(r.object_id, "vm-123");
        assert_eq!(r.to_string(), "vm/vm-123");

        assert!(ObjectRef::parse("noslash").is_none());
        assert!(ObjectRef::parse("/id").is_none());
        assert!(ObjectRef::parse("type/").is_none());
    }

    #[test]
    fn test_subject_ref_parse_direct() {
        let s = SubjectRef::parse("user/alice").unwrap();
        assert_eq!(s.subject_type, "user");
        assert_eq!(s.subject_id, "alice");
        assert!(s.relation.is_none());
        assert_eq!(s.as_direct(), "user/alice");
    }

    #[test]
    fn test_subject_ref_parse_userset() {
        let s = SubjectRef::parse("group/engineers#member").unwrap();
        assert_eq!(s.subject_type, "group");
        assert_eq!(s.subject_id, "engineers");
        assert_eq!(s.relation.as_deref(), Some("member"));
        assert_eq!(s.to_string(), "group/engineers#member");
    }

    #[test]
    fn test_tuple_index() {
        let mut idx = TupleIndex::new();
        let obj = ObjectRef {
            object_type: "vm".into(),
            object_id: "vm-1".into(),
        };
        let subj = SubjectRef {
            subject_type: "user".into(),
            subject_id: "alice".into(),
            relation: None,
        };
        idx.insert(&obj, "owner", &subj);

        let subjects = idx.subjects_for("vm", "vm-1", "owner");
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].subject_id, "alice");

        let objects = idx.objects_for("user", "alice");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].0.object_id, "vm-1");
        assert_eq!(objects[0].1, "owner");

        assert_eq!(idx.tuple_count(), 1);
    }
}
