//! User settings persisted between runs.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::constraints::ConstraintSet;
use crate::domains;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    En,
    Ru,
}

impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    /// Russian for any `ru*` system locale, English otherwise.
    pub fn detect() -> Self {
        match sys_locale::get_locale() {
            Some(locale) if locale.to_lowercase().starts_with("ru") => Self::Ru,
            _ => Self::En,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub language: Option<Language>,
    /// Domains added by the user on top of the curated list.
    #[serde(default)]
    pub custom_domains: Vec<String>,
    /// Curated list downloaded from GitHub.
    #[serde(default)]
    pub downloaded: Option<ConstraintSet>,
    /// [`Browser::id`](crate::browsers::Browser::id)s the policies were last applied to;
    /// empty when not installed. The name predates Windows support and is kept for
    /// compatibility with existing settings files.
    #[serde(default)]
    pub profile_browsers: Vec<String>,
}

/// Entries dropped from a loaded settings file because they failed validation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rejected {
    pub custom_domains: Vec<String>,
    pub downloaded_list: bool,
}

impl Rejected {
    pub fn is_empty(&self) -> bool {
        self.custom_domains.is_empty() && !self.downloaded_list
    }
}

impl Settings {
    pub fn dir() -> Result<PathBuf, Box<dyn Error>> {
        Ok(dirs::config_dir()
            .ok_or("cannot determine the configuration directory")?
            .join("rucert"))
    }

    pub fn path() -> Result<PathBuf, Box<dyn Error>> {
        Ok(Self::dir()?.join("settings.json"))
    }

    pub fn load() -> Result<(Self, Rejected), Box<dyn Error>> {
        Self::load_from(&Self::path()?)
    }

    /// Loads settings and re-validates everything that ends up in the policies, since the
    /// file can be edited by hand.
    pub fn load_from(path: &Path) -> Result<(Self, Rejected), Box<dyn Error>> {
        if !path.exists() {
            return Ok((Self::default(), Rejected::default()));
        }
        let mut settings: Self = serde_json::from_str(&fs::read_to_string(path)?)?;
        let rejected = settings.sanitize();
        Ok((settings, rejected))
    }

    /// Applies the wizard's domain checks to loaded data and drops what fails them.
    fn sanitize(&mut self) -> Rejected {
        let mut rejected = Rejected::default();
        let mut custom = BTreeSet::new();
        for domain in self.custom_domains.drain(..) {
            match domains::normalize(&domain) {
                Ok(normalized) => {
                    custom.insert(normalized);
                }
                Err(_) => rejected.custom_domains.push(domain),
            }
        }
        self.custom_domains = custom.into_iter().collect();
        if let Some(downloaded) = self.downloaded.take() {
            match downloaded.validated() {
                Ok(valid) => self.downloaded = Some(valid),
                Err(_) => rejected.downloaded_list = true,
            }
        }
        rejected
    }

    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(Self::dir()?)?;
        fs::write(Self::path()?, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Newest curated list: a binary may ship a newer list than the downloaded one.
    pub fn curated(&self) -> &ConstraintSet {
        let embedded = ConstraintSet::embedded();
        match &self.downloaded {
            Some(downloaded) if downloaded.version > embedded.version => downloaded,
            _ => embedded,
        }
    }

    /// Curated plus custom domains, sorted and deduplicated.
    pub fn effective_domains(&self) -> Vec<String> {
        self.curated()
            .domains
            .iter()
            .chain(&self.custom_domains)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_prefers_newer_list_only() {
        let embedded = ConstraintSet::embedded();
        let older = Settings {
            downloaded: Some(ConstraintSet {
                version: embedded.version,
                domains: vec!["old.ru".into()],
            }),
            ..Default::default()
        };
        assert_eq!(older.curated(), embedded);

        let newer_set = ConstraintSet {
            version: embedded.version + 1,
            domains: vec!["new.ru".into()],
        };
        let newer = Settings {
            downloaded: Some(newer_set.clone()),
            ..Default::default()
        };
        assert_eq!(newer.curated(), &newer_set);
    }

    #[test]
    fn effective_domains_merge_custom_without_duplicates() {
        let curated = &ConstraintSet::embedded().domains;
        let settings = Settings {
            custom_domains: vec![curated[0].clone(), "aaa-custom.ru".into()],
            ..Default::default()
        };
        let effective = settings.effective_domains();
        assert_eq!(effective.len(), curated.len() + 1);
        assert_eq!(effective[0], "aaa-custom.ru");
    }

    /// A hand-edited file must not smuggle trust-widening entries into the profile.
    #[test]
    fn sanitize_drops_entries_that_fail_validation() {
        let mut settings = Settings {
            custom_domains: vec!["*".into(), "Example.RU".into(), "com".into()],
            downloaded: Some(ConstraintSet {
                version: 99,
                domains: vec!["vtb.ru".into(), "*.ru".into()],
            }),
            ..Default::default()
        };
        assert_eq!(
            settings.sanitize(),
            Rejected {
                custom_domains: vec!["*".into(), "com".into()],
                downloaded_list: true,
            }
        );
        assert_eq!(settings.custom_domains, ["example.ru"]);
        assert_eq!(settings.downloaded, None);
    }

    /// Files written by older versions lack newer fields and must still load.
    #[test]
    fn settings_from_older_versions_load_with_defaults() {
        let settings: Settings =
            serde_json::from_str(r#"{"language":"ru","custom_domains":["example.ru"]}"#).unwrap();
        assert_eq!(settings.language, Some(Language::Ru));
        assert_eq!(settings.custom_domains, ["example.ru"]);
        assert!(settings.downloaded.is_none());
        assert!(settings.profile_browsers.is_empty());
    }
}
