//! Curated domain list: embedded copy and updates from GitHub.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domains;

/// Source of truth: the same file is embedded at build time and served for updates.
const EMBEDDED_JSON: &str = include_str!("../assets/constraints.json");
pub const UPDATE_URL: &str =
    "https://raw.githubusercontent.com/dgavrilov/rucert/master/assets/constraints.json";
const MAX_UPDATE_BYTES: u64 = 1024 * 1024;

static EMBEDDED: LazyLock<ConstraintSet> = LazyLock::new(|| {
    ConstraintSet::parse(EMBEDDED_JSON).expect("embedded constraints.json is valid")
});

/// Versioned list of domains the root CA is allowed to issue for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintSet {
    pub version: u64,
    pub domains: Vec<String>,
}

impl ConstraintSet {
    /// Parses and validates a list; domains come back normalized, sorted, deduplicated.
    pub fn parse(json: &str) -> Result<Self, Box<dyn Error>> {
        serde_json::from_str::<Self>(json)?.validated()
    }

    /// Applies the same checks as [`Self::parse`] to an already deserialized list.
    pub fn validated(self) -> Result<Self, Box<dyn Error>> {
        let mut domains = BTreeSet::new();
        for domain in &self.domains {
            let normalized = domains::normalize(domain).map_err(|e| format!("{domain:?}: {e}"))?;
            domains.insert(normalized);
        }
        if domains.is_empty() {
            return Err("domain list is empty".into());
        }
        Ok(Self {
            version: self.version,
            domains: domains.into_iter().collect(),
        })
    }

    pub fn embedded() -> &'static Self {
        &EMBEDDED
    }
}

/// Downloads the published list. The caller decides whether it is newer.
pub fn fetch() -> Result<ConstraintSet, Box<dyn Error>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into();
    let body = agent
        .get(UPDATE_URL)
        .call()?
        .body_mut()
        .with_config()
        .limit(MAX_UPDATE_BYTES)
        .read_to_string()?;
    ConstraintSet::parse(&body)
}

/// Domains added and removed when moving from `old` to `new`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

pub fn diff(old: &[String], new: &[String]) -> Diff {
    let old: BTreeSet<&String> = old.iter().collect();
    let new: BTreeSet<&String> = new.iter().collect();
    Diff {
        added: new.difference(&old).map(|d| (*d).clone()).collect(),
        removed: old.difference(&new).map(|d| (*d).clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_list_is_valid() {
        assert!(!ConstraintSet::embedded().domains.is_empty());
    }

    #[test]
    fn parse_normalizes_and_rejects_widening_entries() {
        let set =
            ConstraintSet::parse(r#"{"version":2,"domains":["VTB.ru","vtb.ru","a.ru"]}"#).unwrap();
        assert_eq!(set.domains, ["a.ru", "vtb.ru"]);
        assert!(ConstraintSet::parse(r#"{"version":2,"domains":["*"]}"#).is_err());
        assert!(ConstraintSet::parse(r#"{"version":2,"domains":["com"]}"#).is_err());
        assert!(ConstraintSet::parse(r#"{"version":2,"domains":[]}"#).is_err());
    }

    #[test]
    fn diff_reports_both_directions() {
        let old = ["a.ru".to_string(), "b.ru".to_string()];
        let new = ["b.ru".to_string(), "c.ru".to_string()];
        assert_eq!(
            diff(&old, &new),
            Diff {
                added: vec!["c.ru".into()],
                removed: vec!["a.ru".into()]
            }
        );
    }
}
