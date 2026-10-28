//! Windows: policies live under `HKLM\SOFTWARE\Policies`. Writing there needs administrator
//! rights, so only that step runs elevated: the wizard starts a copy of itself through UAC
//! with the browser IDs and the path of the settings file, and the copy re-validates both.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

use sha1::{Digest, Sha1};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY,
};
use winreg::types::FromRegValue;

use crate::browsers::{BROWSERS, Browser};
use crate::policy::{self, AppliedPolicy, CONSTRAINED_KEY, HINTS_KEY, INTERMEDIATES, ROOT_CA};
use crate::settings::Settings;

const APPLY_ARG: &str = "--elevated-apply";
const REMOVE_ARG: &str = "--elevated-remove";
const APP_PATHS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const READ: u32 = KEY_READ | KEY_WOW64_64KEY;
const WRITE: u32 = KEY_ALL_ACCESS | KEY_WOW64_64KEY;

/// Supported browsers registered under `App Paths` or, for products sharing a policy key,
/// under `Uninstall`.
pub fn installed_browsers() -> Vec<&'static Browser> {
    BROWSERS
        .iter()
        .filter(|browser| {
            let app_paths = browser
                .app_paths
                .iter()
                .map(|exe| format!(r"{APP_PATHS}\{exe}"));
            let uninstall = browser
                .uninstall_keys
                .iter()
                .map(|entry| format!(r"{UNINSTALL}\{entry}"));
            app_paths.chain(uninstall).any(|path| registered(&path))
        })
        .collect()
}

/// Per-machine installs register in HKLM (in either registry view, as some installers are
/// 32-bit), per-user installs in HKCU.
fn registered(path: &str) -> bool {
    [
        (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        (HKEY_CURRENT_USER, 0),
    ]
    .into_iter()
    .any(|(root, view)| {
        RegKey::predef(root)
            .open_subkey_with_flags(path, KEY_READ | view)
            .is_ok()
    })
}

/// Whether Russian Trusted Root CA is in a Windows trusted root store (per user, per machine
/// or set by group policy). Then every application trusts it for any site, and the domain
/// constraints of the policies do not restrict anything.
pub fn root_trusted_system_wide() -> bool {
    // Stores keep each certificate in a subkey named after its SHA-1 thumbprint.
    let thumbprint = Sha1::digest(ROOT_CA.der())
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02X}");
            hex
        });
    [
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\SystemCertificates\Root",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SystemCertificates\Root",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\EnterpriseCertificates\Root",
        ),
    ]
    .into_iter()
    .any(|(root, store)| {
        RegKey::predef(root)
            .open_subkey_with_flags(format!(r"{store}\Certificates\{thumbprint}"), READ)
            .is_ok()
    })
}

/// Policy enforced for our root CA in the browser's policy key, if any.
pub fn applied(browser: &Browser) -> Option<AppliedPolicy> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(browser.policy_key, READ)
        .ok()?;
    applied_in(&key)
}

fn applied_in(key: &RegKey) -> Option<AppliedPolicy> {
    let json: String = key.get_value(CONSTRAINED_KEY).ok()?;
    let hints: Vec<String> = key
        .open_subkey_with_flags(HINTS_KEY, READ)
        .map(|hints| {
            hints
                .enum_values()
                .filter_map(Result::ok)
                .filter_map(|(_, value)| String::from_reg_value(&value).ok())
                .collect()
        })
        .unwrap_or_default();
    let hints: Vec<&str> = hints.iter().map(String::as_str).collect();
    policy::evaluate(policy::parse_constrained_json(&json), &hints)
}

/// Writes the policies for `selected` and clears ours from the other browsers, through UAC.
/// A declined UAC prompt is reported as [`io::ErrorKind::Interrupted`].
pub fn apply(selected: &[&Browser]) -> io::Result<()> {
    let ids: Vec<&str> = selected.iter().map(|browser| browser.id).collect();
    let settings = Settings::path().map_err(|e| io::Error::other(e.to_string()))?;
    // The domain list may be long, so it is not put on the command line: the elevated
    // process reads it from this user's settings file. The path is passed explicitly
    // because UAC may elevate as another account, with its own %APPDATA%. Windows paths
    // cannot contain `"`, so quoting is enough.
    run_elevated(&format!(
        "{APPLY_ARG} {} \"{}\"",
        ids.join(","),
        settings.display()
    ))
}

/// Clears our policies from every supported browser, through UAC.
pub fn remove() -> io::Result<()> {
    run_elevated(REMOVE_ARG)
}

/// Runs the elevated step when the process was started with one of its flags.
pub fn run_elevated_command() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some(APPLY_ARG) => parse_apply_args(&args[1..])
            .and_then(|(browsers, domains)| write_policies(&browsers, &domains)),
        Some(REMOVE_ARG) => BROWSERS.iter().try_for_each(clear_policies),
        _ => return None,
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    })
}

/// Arguments and the settings file come from the unelevated side, so both are checked
/// again: this process has administrator rights and must not write anything the wizard
/// would not.
fn parse_apply_args(args: &[String]) -> io::Result<(Vec<&'static Browser>, Vec<String>)> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    let [ids, settings] = args else {
        return Err(invalid());
    };
    let browsers = ids
        .split(',')
        .map(|id| BROWSERS.iter().find(|b| b.id == id).ok_or_else(invalid))
        .collect::<io::Result<Vec<_>>>()?;
    // Loading validates every domain and drops what fails, as in the wizard.
    let (settings, _) =
        Settings::load_from(Path::new(settings)).map_err(|e| io::Error::other(e.to_string()))?;
    Ok((browsers, settings.effective_domains()))
}

fn write_policies(selected: &[&Browser], domains: &[String]) -> io::Result<()> {
    for browser in BROWSERS {
        if !selected.contains(&browser) {
            clear_policies(browser)?;
            continue;
        }
        let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .create_subkey_with_flags(browser.policy_key, WRITE)?;
        key.set_value(CONSTRAINED_KEY, &policy::constrained_json(domains))?;
        ignore_missing(key.delete_subkey_all(HINTS_KEY))?;
        let (hints, _) = key.create_subkey_with_flags(HINTS_KEY, WRITE)?;
        for (index, certificate) in INTERMEDIATES.iter().enumerate() {
            hints.set_value((index + 1).to_string(), &certificate.base64())?;
        }
    }
    Ok(())
}

/// Removes our policy values; values for other CAs and other policies are left alone.
fn clear_policies(browser: &Browser) -> io::Result<()> {
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(browser.policy_key, WRITE)
    {
        Ok(key) => key,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if applied_in(&key).is_none() {
        return Ok(());
    }
    key.delete_value(CONSTRAINED_KEY)?;
    ignore_missing(key.delete_subkey_all(HINTS_KEY))
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

/// Starts this executable elevated with `parameters`, hidden, and waits for it.
fn run_elevated(parameters: &str) -> io::Result<()> {
    let exe = wide(std::env::current_exe()?.as_os_str());
    let parameters = wide(OsStr::new(parameters));
    let verb = wide(OsStr::new("runas"));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).map_err(io::Error::other)?,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: exe.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: `info` is initialized with its own size, and every string it points to is
    // NUL-terminated and outlives the call.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
        let error = io::Error::last_os_error();
        return Err(
            if error.raw_os_error() == i32::try_from(ERROR_CANCELLED).ok() {
                io::Error::from(io::ErrorKind::Interrupted)
            } else {
                error
            },
        );
    }
    let process = info.hProcess;
    if process.is_null() {
        return Err(io::Error::other("UAC did not return a process handle"));
    }
    let mut code = 0u32;
    // SAFETY: `process` is a live handle owned by us (SEE_MASK_NOCLOSEPROCESS); `code` is a
    // valid out pointer.
    let got_code = unsafe {
        WaitForSingleObject(process, INFINITE);
        GetExitCodeProcess(process, &raw mut code)
    };
    // SAFETY: the handle is closed exactly once and not used afterwards.
    unsafe { CloseHandle(process) };
    if got_code == 0 {
        return Err(io::Error::last_os_error());
    }
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "elevated process exited with code {code}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The elevated process accepts only known browsers and takes the domains from the
    /// given settings file, validated as on load.
    #[test]
    fn elevated_arguments_are_revalidated() {
        let path =
            std::env::temp_dir().join(format!("rucert-elevated-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"custom_domains":["custom.ru","*.ru"]}"#).unwrap();
        let settings = path.to_str().unwrap();

        let (browsers, domains) =
            parse_apply_args(&args(&["com.google.Chrome,com.brave.Browser", settings])).unwrap();
        assert_eq!(browsers.len(), 2);
        assert!(domains.contains(&"custom.ru".to_string()));
        assert!(!domains.iter().any(|d| d.contains('*')));

        assert!(parse_apply_args(&args(&["com.example.Unknown", settings])).is_err());
        assert!(parse_apply_args(&args(&["com.google.Chrome"])).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
