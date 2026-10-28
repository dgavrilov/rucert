//! macOS: policies are delivered as forced managed preferences in a configuration profile,
//! which the user approves in System Settings.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use plist::{Dictionary, Value};
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use crate::browsers::{BROWSERS, Browser};
use crate::policy::{self, AppliedPolicy, CONSTRAINED_KEY, HINTS_KEY, INTERMEDIATES, ROOT_CA};

pub const PROFILE_ID: &str = "io.github.dgavrilov.rucert";
const MANAGED_PREFS_DIR: &str = "/Library/Managed Preferences";
/// Pane listing configuration profiles (macOS 13+).
const PROFILES_PANE_URL: &str = "x-apple.systempreferences:com.apple.Profiles-Settings.extension";
// Absolute paths: `sudo` must not be resolved through a user-controlled `PATH`.
const OPEN: &str = "/usr/bin/open";
const SUDO: &str = "/usr/bin/sudo";
const PROFILES: &str = "/usr/bin/profiles";

/// Supported browsers found in `/Applications` or `~/Applications`.
pub fn installed_browsers() -> Vec<&'static Browser> {
    let mut dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Applications"));
    }
    browsers_with_apps(&bundle_ids_in(&dirs))
}

/// Browsers with at least one of their apps (channels) among `ids`.
fn browsers_with_apps(ids: &BTreeSet<String>) -> Vec<&'static Browser> {
    BROWSERS
        .iter()
        .filter(|browser| browser.app_ids.iter().any(|id| ids.contains(*id)))
        .collect()
}

/// `CFBundleIdentifier`s of the apps in `dirs`; `.app` names vary, identifiers do not.
fn bundle_ids_in(dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "app") {
                continue;
            }
            let info = path.join("Contents/Info.plist");
            if let Some(id) = Value::from_file(info).ok().and_then(|v| {
                v.as_dictionary()?
                    .get("CFBundleIdentifier")?
                    .as_string()
                    .map(str::to_owned)
            }) {
                ids.insert(id);
            }
        }
    }
    ids
}

fn dict<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Dictionary(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn string(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

fn uuid() -> Value {
    string(uuid::Uuid::new_v4().to_string().to_uppercase())
}

fn constrained_value(domains: &[String]) -> Value {
    Value::Array(vec![dict([
        ("certificate", string(ROOT_CA.base64())),
        (
            "constraints",
            dict([(
                "permitted_dns_names",
                Value::Array(domains.iter().cloned().map(Value::String).collect()),
            )]),
        ),
    ])])
}

fn hints_value() -> Value {
    Value::Array(INTERMEDIATES.iter().map(|c| string(c.base64())).collect())
}

/// Builds one profile with a forced preference payload per browser.
///
/// The fixed `PayloadIdentifier` makes a reinstall replace the previous profile.
pub fn build(browsers: &[&Browser], domains: &[String]) -> Value {
    let payloads = browsers
        .iter()
        .map(|browser| {
            dict([
                ("PayloadType", string("com.apple.ManagedClient.preferences")),
                ("PayloadVersion", Value::Integer(1.into())),
                (
                    "PayloadIdentifier",
                    string(format!("{PROFILE_ID}.{}", browser.id)),
                ),
                ("PayloadUUID", uuid()),
                (
                    "PayloadDisplayName",
                    string(format!("{}: Russian Trusted Root CA", browser.name)),
                ),
                (
                    "PayloadContent",
                    dict([(
                        browser.id,
                        dict([(
                            "Forced",
                            Value::Array(vec![dict([(
                                "mcx_preference_settings",
                                dict([
                                    (CONSTRAINED_KEY, constrained_value(domains)),
                                    (HINTS_KEY, hints_value()),
                                ]),
                            )])]),
                        )]),
                    )]),
                ),
            ])
        })
        .collect();

    dict([
        ("PayloadType", string("Configuration")),
        ("PayloadVersion", Value::Integer(1.into())),
        ("PayloadIdentifier", string(PROFILE_ID)),
        ("PayloadUUID", uuid()),
        (
            "PayloadDisplayName",
            string("rucert: Russian Trusted Root CA"),
        ),
        (
            "PayloadDescription",
            string(
                "Trusts Russian Trusted Root CA only in the selected browsers \
                 and only for the listed domains. Intermediate CAs are added as \
                 path-building hints only. The system trust store is not modified.",
            ),
        ),
        ("PayloadOrganization", string("rucert")),
        ("PayloadRemovalDisallowed", Value::Boolean(false)),
        ("PayloadScope", string("System")),
        ("PayloadContent", Value::Array(payloads)),
    ])
}

/// Writes the profile and hands it to macOS, which registers it for approval.
pub fn write_and_open(profile: &Value, dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let path = dir.join("rucert.mobileconfig");
    profile.to_file_xml(&path)?;
    run(OPEN, &[path.as_os_str()])?;
    Ok(path)
}

pub fn open_profiles_pane() -> io::Result<()> {
    run(OPEN, &[PROFILES_PANE_URL.as_ref()])
}

/// Removes the profile; `sudo` prompts for the password in the terminal.
pub fn remove() -> io::Result<()> {
    run(
        SUDO,
        &[
            PROFILES.as_ref(),
            "remove".as_ref(),
            "-identifier".as_ref(),
            PROFILE_ID.as_ref(),
        ],
    )
}

fn run(program: &str, args: &[&std::ffi::OsStr]) -> io::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} exited with {status}")))
    }
}

/// Whether Russian Trusted Root CA is trusted for TLS through keychain trust settings
/// (user or admin domain). Then every application trusts it for any site, and the domain
/// constraints of the policies do not restrict anything.
pub fn root_trusted_system_wide() -> bool {
    [Domain::User, Domain::Admin].into_iter().any(|domain| {
        let settings = TrustSettings::new(domain);
        let Ok(certificates) = settings.iter() else {
            return false;
        };
        certificates
            .filter(|certificate| certificate.to_der() == ROOT_CA.der())
            .any(|certificate| {
                matches!(
                    settings.tls_trust_settings_for_certificate(&certificate),
                    Ok(Some(
                        TrustSettingsForCertificate::TrustRoot
                            | TrustSettingsForCertificate::TrustAsRoot
                    ))
                )
            })
    })
}

/// Policy enforced for our root CA in the browser's preference domain, if any.
pub fn applied(browser: &Browser) -> Option<AppliedPolicy> {
    applied_in(&Path::new(MANAGED_PREFS_DIR).join(format!("{}.plist", browser.id)))
}

fn applied_in(managed_prefs: &Path) -> Option<AppliedPolicy> {
    let prefs = Value::from_file(managed_prefs).ok()?;
    let prefs = prefs.as_dictionary()?;
    let constrained = prefs
        .get(CONSTRAINED_KEY)?
        .as_array()?
        .iter()
        .filter_map(Value::as_dictionary)
        .filter_map(|entry| {
            let certificate = entry.get("certificate")?.as_string()?;
            Some((certificate, dns_names(entry).unwrap_or_default()))
        });
    let hints: Vec<&str> = prefs
        .get(HINTS_KEY)
        .and_then(Value::as_array)
        .map(|hints| hints.iter().filter_map(Value::as_string).collect())
        .unwrap_or_default();
    policy::evaluate(constrained, &hints)
}

fn dns_names(entry: &Dictionary) -> Option<Vec<String>> {
    let names = entry
        .get("constraints")?
        .as_dictionary()?
        .get("permitted_dns_names")?
        .as_array()?;
    Some(
        names
            .iter()
            .filter_map(Value::as_string)
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rucert-{test}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The managed preferences macOS derives from a payload are its `mcx_preference_settings`;
    /// reading them back must yield exactly the domains and hints we put in.
    #[test]
    fn built_profile_round_trips_through_managed_prefs_reader() {
        let domains = vec!["gosuslugi.ru".to_string(), "vtb.ru".to_string()];
        let browsers: Vec<&Browser> = BROWSERS.iter().collect();
        let profile = build(&browsers, &domains);

        let payloads = profile.as_dictionary().unwrap()["PayloadContent"]
            .as_array()
            .unwrap();
        assert_eq!(payloads.len(), BROWSERS.len());

        let dir = temp_dir("round-trip");
        for (payload, browser) in payloads.iter().zip(BROWSERS) {
            let settings = &payload.as_dictionary().unwrap()["PayloadContent"]
                .as_dictionary()
                .unwrap()[browser.id]
                .as_dictionary()
                .unwrap()["Forced"]
                .as_array()
                .unwrap()[0]
                .as_dictionary()
                .unwrap()["mcx_preference_settings"];
            let path = dir.join(format!("{}.plist", browser.id));
            settings.to_file_xml(&path).unwrap();
            assert_eq!(
                applied_in(&path),
                Some(AppliedPolicy {
                    domains: domains.clone(),
                    hints_complete: true,
                })
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    /// Reinstalling must replace the previous profile (stable identifiers), while every
    /// payload needs its own UUID or macOS rejects the profile.
    #[test]
    fn profile_identifiers_are_stable_and_uuids_unique() {
        let browsers: Vec<&Browser> = BROWSERS.iter().collect();
        let domains = ["vtb.ru".to_string()];
        let identifiers = |profile: &Value| {
            let root = profile.as_dictionary().unwrap();
            let mut ids = vec![root["PayloadIdentifier"].as_string().unwrap().to_owned()];
            let mut uuids = vec![root["PayloadUUID"].as_string().unwrap().to_owned()];
            for payload in root["PayloadContent"].as_array().unwrap() {
                let payload = payload.as_dictionary().unwrap();
                ids.push(payload["PayloadIdentifier"].as_string().unwrap().to_owned());
                uuids.push(payload["PayloadUUID"].as_string().unwrap().to_owned());
            }
            (ids, uuids)
        };

        let (first_ids, first_uuids) = identifiers(&build(&browsers, &domains));
        let (second_ids, second_uuids) = identifiers(&build(&browsers, &domains));
        assert_eq!(first_ids, second_ids);
        assert_eq!(first_ids[0], PROFILE_ID);

        let all_uuids: BTreeSet<_> = first_uuids.iter().chain(&second_uuids).collect();
        assert_eq!(all_uuids.len(), first_uuids.len() + second_uuids.len());
    }

    fn app(dir: &Path, name: &str, info_plist: &str) {
        let contents = dir.join(name).join("Contents");
        fs::create_dir_all(&contents).unwrap();
        fs::write(contents.join("Info.plist"), info_plist).unwrap();
    }

    fn info_plist(bundle_id: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>{bundle_id}</string></dict></plist>"#
        )
    }

    /// Bundles are found by identifier; broken bundles, non-`.app` entries and
    /// missing directories are skipped instead of failing the scan.
    #[test]
    fn scan_reads_bundle_ids_and_skips_junk() {
        let dir = temp_dir("apps");
        app(
            &dir,
            "Renamed Browser.app",
            &info_plist("com.brave.Browser.origin"),
        );
        app(&dir, "Broken.app", "not a plist");
        app(&dir, "NotAnApp", &info_plist("com.example.ignored"));

        let ids = bundle_ids_in(&[dir.clone(), dir.join("missing")]);
        assert_eq!(
            ids,
            BTreeSet::from(["com.brave.Browser.origin".to_string()])
        );
        fs::remove_dir_all(dir).unwrap();
    }

    /// Edge apps are `com.microsoft.edgemac*`, but policies live in `com.microsoft.Edge`:
    /// detection must use the app IDs, and any channel counts.
    #[test]
    fn edge_is_detected_by_any_channel_app_id() {
        let found = |id: &str| browsers_with_apps(&BTreeSet::from([id.to_string()]));
        let edge = found("com.microsoft.edgemac.Beta");
        assert_eq!(edge.len(), 1);
        assert_eq!(edge[0].id, "com.microsoft.Edge");
        assert!(found("com.microsoft.Edge").is_empty());
    }
}
