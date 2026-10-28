#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("rucert supports macOS and Windows only");

mod browsers;
mod constraints;
mod domains;
#[cfg(target_os = "macos")]
mod macos;
mod policy;
mod settings;
#[cfg(windows)]
mod windows;
mod wizard;

rust_i18n::i18n!("locales", fallback = "en");

fn main() -> std::process::ExitCode {
    // The UAC-elevated copy of the wizard only writes the registry and exits.
    #[cfg(windows)]
    if let Some(code) = windows::run_elevated_command() {
        return code;
    }
    // The wizard writes to stderr; frame it with one blank line on each side.
    eprintln!();
    let outcome = wizard::run();
    if let Err(e) = &outcome {
        eprintln!("{e}");
    }
    eprintln!();
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    /// Keys of a flat `_version: 1` locale file with the placeholders each message uses.
    fn messages(yaml: &str) -> BTreeMap<&str, Vec<&str>> {
        yaml.lines()
            .filter(|line| !line.starts_with('_') && !line.trim().is_empty())
            .map(|line| {
                let (key, value) = line.split_once(": ").expect("`key: value` line");
                let mut placeholders: Vec<&str> = value
                    .split("%{")
                    .skip(1)
                    .filter_map(|rest| rest.split_once('}').map(|(name, _)| name))
                    .collect();
                placeholders.sort_unstable();
                (key, placeholders)
            })
            .collect()
    }

    /// A key missing in one language or a placeholder renamed in only one translation
    /// shows up as a raw key or a literal `%{name}` in the wizard.
    #[test]
    fn locales_have_same_keys_and_placeholders() {
        let en = messages(include_str!("../locales/en.yaml"));
        let ru = messages(include_str!("../locales/ru.yaml"));
        assert_eq!(en, ru);
    }
}
