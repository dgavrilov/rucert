//! Platform-independent content of the Chromium policies: which certificates go where
//! and how values read back from the OS are interpreted.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// Trust anchors with DNS constraints.
pub const CONSTRAINED_KEY: &str = "CACertificatesWithConstraints";
/// Certificates used only for path building, never trusted on their own.
pub const HINTS_KEY: &str = "CAHintCertificates";

/// Certificate published at https://www.gosuslugi.ru/crt.
pub struct Certificate {
    pub name: &'static str,
    der: &'static [u8],
}

impl Certificate {
    pub fn der(&self) -> &'static [u8] {
        self.der
    }

    pub fn base64(&self) -> String {
        STANDARD.encode(self.der)
    }

    pub fn sha256(&self) -> String {
        Sha256::digest(self.der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// The only trust anchor; the domain constraints are attached to it.
pub const ROOT_CA: Certificate = Certificate {
    name: "Russian Trusted Root CA",
    der: include_bytes!("../assets/russian_trusted_root_ca.der"),
};

/// Issued by [`ROOT_CA`]. Passed as hints so chains build even when a server omits
/// the intermediate; every chain still ends at the constrained root.
pub const INTERMEDIATES: [Certificate; 2] = [
    Certificate {
        name: "Russian Trusted Sub CA (2022)",
        der: include_bytes!("../assets/russian_trusted_sub_ca.der"),
    },
    Certificate {
        name: "Russian Trusted Sub CA (2024)",
        der: include_bytes!("../assets/russian_trusted_sub_ca_2024.der"),
    },
];

/// Our policy as currently enforced for a browser.
#[derive(Debug, PartialEq, Eq)]
pub struct AppliedPolicy {
    /// `permitted_dns_names` attached to [`ROOT_CA`].
    pub domains: Vec<String>,
    /// Whether every certificate from [`INTERMEDIATES`] is present in `CAHintCertificates`.
    pub hints_complete: bool,
}

/// Interprets policy values read back from the OS.
///
/// `constrained` yields `(certificate, permitted_dns_names)` per `CACertificatesWithConstraints`
/// entry. Returns `None` when no entry is for [`ROOT_CA`], i.e. the policy is not ours.
pub fn evaluate<C: AsRef<str>>(
    constrained: impl IntoIterator<Item = (C, Vec<String>)>,
    hints: &[&str],
) -> Option<AppliedPolicy> {
    let root = ROOT_CA.base64();
    let (_, domains) = constrained
        .into_iter()
        .find(|(certificate, _)| certificate.as_ref() == root)?;
    let hints_complete = INTERMEDIATES
        .iter()
        .all(|cert| hints.contains(&cert.base64().as_str()));
    Some(AppliedPolicy {
        domains,
        hints_complete,
    })
}

/// `CACertificatesWithConstraints` as the JSON string Windows policies expect.
#[cfg(any(windows, test))]
pub fn constrained_json(domains: &[String]) -> String {
    serde_json::json!([{
        "certificate": ROOT_CA.base64(),
        "constraints": { "permitted_dns_names": domains },
    }])
    .to_string()
}

/// Parses a `CACertificatesWithConstraints` JSON string into `(certificate, domains)` pairs.
/// Malformed entries are skipped: they cannot be ours.
#[cfg(any(windows, test))]
pub fn parse_constrained_json(json: &str) -> Vec<(String, Vec<String>)> {
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_str(json) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let certificate = entry.get("certificate")?.as_str()?.to_owned();
            let domains = entry
                .pointer("/constraints/permitted_dns_names")
                .and_then(serde_json::Value::as_array)
                .map(|names| {
                    names
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            Some((certificate, domains))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_certificates_match_pinned_fingerprints() {
        assert_eq!(
            ROOT_CA.sha256(),
            "D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:\
             5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31"
        );
        assert_eq!(
            INTERMEDIATES[0].sha256(),
            "BB:BD:E2:10:3E:79:0B:99:9E:C6:2B:D0:3C:F6:25:A5:A2:E7:C3:16:\
             E1:0A:FE:6A:49:0E:ED:EA:D8:B3:FD:9B"
        );
        assert_eq!(
            INTERMEDIATES[1].sha256(),
            "21:55:78:50:36:C9:00:DB:B5:F1:BB:2A:15:69:C8:0C:55:59:5B:D6:\
             BF:94:86:7A:29:BB:DD:BC:7D:88:A3:F2"
        );
    }

    /// Policies for some other CA, or with only part of the hints, must not be reported
    /// as our fully applied policy.
    #[test]
    fn foreign_root_is_ignored_and_partial_hints_are_incomplete() {
        let foreign = INTERMEDIATES[0].base64();
        assert_eq!(evaluate([(foreign.as_str(), Vec::new())], &[]), None);

        let root = ROOT_CA.base64();
        let first_hint = INTERMEDIATES[0].base64();
        assert_eq!(
            evaluate([(root.as_str(), vec!["vtb.ru".into()])], &[&first_hint]),
            Some(AppliedPolicy {
                domains: vec!["vtb.ru".into()],
                hints_complete: false,
            })
        );
    }

    /// The JSON written to the Windows registry must read back as our policy.
    #[test]
    fn constrained_json_round_trips() {
        let domains = vec!["gosuslugi.ru".to_string(), "vtb.ru".to_string()];
        let parsed = parse_constrained_json(&constrained_json(&domains));
        let hints: Vec<String> = INTERMEDIATES.iter().map(Certificate::base64).collect();
        let hints: Vec<&str> = hints.iter().map(String::as_str).collect();
        assert_eq!(
            evaluate(parsed, &hints),
            Some(AppliedPolicy {
                domains,
                hints_complete: true,
            })
        );
        assert!(parse_constrained_json("not json").is_empty());
    }
}
