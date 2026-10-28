//! Validation and normalization of DNS names used as `permitted_dns_names`.

use std::fmt;

/// Reason a domain cannot be used as a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    Empty,
    Wildcard,
    TopLevelOnly,
    IpAddress,
    Invalid,
}

impl DomainError {
    /// Localization key describing the error.
    pub fn message_key(self) -> &'static str {
        match self {
            Self::Empty => "domain_error.empty",
            Self::Wildcard => "domain_error.wildcard",
            Self::TopLevelOnly => "domain_error.top_level",
            Self::IpAddress => "domain_error.ip",
            Self::Invalid => "domain_error.invalid",
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty domain",
            Self::Wildcard => "wildcards are not allowed",
            Self::TopLevelOnly => "top-level domains are not allowed",
            Self::IpAddress => "IP addresses are not allowed",
            Self::Invalid => "invalid domain name",
        })
    }
}

impl std::error::Error for DomainError {}

/// Converts user input into the ASCII (punycode) lowercase form Chromium expects.
///
/// A constraint covers the domain and all its subdomains, so anything that would
/// widen trust beyond a registrable name (wildcards, bare TLDs, IPs) is rejected.
pub fn normalize(input: &str) -> Result<String, DomainError> {
    let trimmed = input.trim().trim_start_matches('.').trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DomainError::Empty);
    }
    if trimmed.contains('*') {
        return Err(DomainError::Wildcard);
    }
    let ascii = idna::domain_to_ascii(trimmed).map_err(|_| DomainError::Invalid)?;
    if ascii.len() > 253 {
        return Err(DomainError::Invalid);
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    for label in &labels {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(DomainError::Invalid);
        }
    }
    if labels.len() < 2 {
        return Err(DomainError::TopLevelOnly);
    }
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(DomainError::IpAddress);
    }
    Ok(ascii)
}

/// Human-readable form of a normalized domain: `госуслуги.рф (xn--c1aapkosapc.xn--p1ai)`
/// for internationalized names, the name itself otherwise.
pub fn display(ascii: &str) -> String {
    match idna::domain_to_unicode(ascii) {
        (unicode, Ok(())) if unicode != ascii => format!("{unicode} ({ascii})"),
        _ => ascii.to_owned(),
    }
}

/// The entry of `list` that already covers `domain`: the domain itself or a parent of it,
/// since a constraint on a name also allows all its subdomains.
pub fn covered_by<'a>(domain: &str, list: &'a [String]) -> Option<&'a String> {
    list.iter().find(|entry| {
        domain == entry.as_str()
            || domain
                .strip_suffix(entry.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_dots_and_idn() {
        assert_eq!(normalize("  GosUslugi.RU. ").unwrap(), "gosuslugi.ru");
        assert_eq!(normalize(".nalog.gov.ru").unwrap(), "nalog.gov.ru");
        assert_eq!(
            normalize("госуслуги.рф").unwrap(),
            "xn--c1aapkosapc.xn--p1ai"
        );
    }

    #[test]
    fn rejects_trust_widening_input() {
        assert_eq!(normalize("*.ru"), Err(DomainError::Wildcard));
        assert_eq!(normalize("ru"), Err(DomainError::TopLevelOnly));
        assert_eq!(normalize("рф"), Err(DomainError::TopLevelOnly));
        assert_eq!(normalize("10.0.0.1"), Err(DomainError::IpAddress));
        assert_eq!(normalize(""), Err(DomainError::Empty));
        assert_eq!(normalize("a..ru"), Err(DomainError::Invalid));
        assert_eq!(normalize("-bad.ru"), Err(DomainError::Invalid));
        assert_eq!(normalize("bad_name.ru"), Err(DomainError::Invalid));
    }

    #[test]
    fn enforces_dns_length_limits() {
        let label63 = "a".repeat(63);
        assert!(normalize(&format!("{label63}.ru")).is_ok());
        assert_eq!(
            normalize(&format!("{label63}a.ru")),
            Err(DomainError::Invalid)
        );

        // 63 + 63 + 63 + 61 characters plus three dots: exactly 253.
        let longest = format!("{label63}.{label63}.{label63}.{}", "a".repeat(61));
        assert_eq!(longest.len(), 253);
        assert!(normalize(&longest).is_ok());
        assert!(normalize(&format!("a{longest}")).is_err());
    }

    #[test]
    fn idn_case_variants_normalize_to_one_name() {
        assert_eq!(
            normalize("ГОСУСЛУГИ.РФ").unwrap(),
            normalize("госуслуги.рф").unwrap()
        );
    }

    #[test]
    fn display_shows_both_forms_only_for_idn() {
        assert_eq!(
            display("xn--c1aapkosapc.xn--p1ai"),
            "госуслуги.рф (xn--c1aapkosapc.xn--p1ai)"
        );
        assert_eq!(display("gosuslugi.ru"), "gosuslugi.ru");
        // Malformed punycode is shown as is rather than half-decoded.
        assert_eq!(display("xn--zz.ru"), "xn--zz.ru");
    }

    #[test]
    fn coverage_follows_label_boundaries() {
        let list = ["sberbank.ru".to_string(), "gov.ru".to_string()];
        assert_eq!(covered_by("sberbank.ru", &list), Some(&list[0]));
        assert_eq!(covered_by("online.sberbank.ru", &list), Some(&list[0]));
        assert_eq!(covered_by("a.b.gov.ru", &list), Some(&list[1]));
        assert_eq!(covered_by("evilsberbank.ru", &list), None);
        assert_eq!(covered_by("ru", &list), None);
    }
}
