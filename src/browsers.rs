//! Supported browsers per platform.

/// A Chromium-based browser that supports `CACertificatesWithConstraints`.
#[derive(Debug, PartialEq, Eq)]
pub struct Browser {
    pub name: &'static str,
    /// Stable identifier persisted in the settings. On macOS it is also the managed
    /// preference domain the browser reads policies from.
    pub id: &'static str,
    /// Internal page that shows applied policies.
    pub policy_url: &'static str,
    /// `CFBundleIdentifier`s of the apps (channels) reading the preference domain.
    #[cfg(target_os = "macos")]
    pub app_ids: &'static [&'static str],
    /// Policy key under `HKEY_LOCAL_MACHINE`.
    #[cfg(windows)]
    pub policy_key: &'static str,
    /// Executables registered under `App Paths` by the installer.
    #[cfg(windows)]
    pub app_paths: &'static [&'static str],
    /// `...\CurrentVersion\Uninstall` entries of products that read the same policy key.
    #[cfg(windows)]
    pub uninstall_keys: &'static [&'static str],
}

#[cfg(target_os = "macos")]
pub const BROWSERS: &[Browser] = &[
    Browser {
        name: "Google Chrome",
        id: "com.google.Chrome",
        policy_url: "chrome://policy",
        app_ids: &["com.google.Chrome"],
    },
    Browser {
        name: "Microsoft Edge",
        // Every Edge channel reads `com.microsoft.Edge`, while the apps are `edgemac*`.
        id: "com.microsoft.Edge",
        policy_url: "edge://policy",
        app_ids: &[
            "com.microsoft.edgemac",
            "com.microsoft.edgemac.Beta",
            "com.microsoft.edgemac.Dev",
            "com.microsoft.edgemac.Canary",
        ],
    },
    Browser {
        name: "Brave",
        id: "com.brave.Browser",
        policy_url: "brave://policy",
        app_ids: &["com.brave.Browser"],
    },
    Browser {
        name: "Brave Origin",
        id: "com.brave.Browser.origin",
        policy_url: "brave://policy",
        app_ids: &["com.brave.Browser.origin"],
    },
];

#[cfg(windows)]
pub const BROWSERS: &[Browser] = &[
    Browser {
        name: "Google Chrome",
        id: "com.google.Chrome",
        policy_url: "chrome://policy",
        policy_key: r"SOFTWARE\Policies\Google\Chrome",
        app_paths: &["chrome.exe"],
        uninstall_keys: &[],
    },
    Browser {
        name: "Microsoft Edge",
        id: "com.microsoft.Edge",
        policy_url: "edge://policy",
        policy_key: r"SOFTWARE\Policies\Microsoft\Edge",
        app_paths: &["msedge.exe"],
        uninstall_keys: &[],
    },
    // Brave Origin's standalone build reads the same `BraveSoftware\Brave` key (its policy
    // key is not branded, unlike its install paths), so one entry covers both. Origin is
    // found by its uninstall entries, named after its `Brave-Origin*` install modes.
    Browser {
        name: "Brave / Brave Origin",
        id: "com.brave.Browser",
        policy_url: "brave://policy",
        policy_key: r"SOFTWARE\Policies\BraveSoftware\Brave",
        app_paths: &["brave.exe"],
        uninstall_keys: &[
            "BraveSoftware Brave-Origin",
            "BraveSoftware Brave-Origin-Beta",
            "BraveSoftware Brave-Origin-Dev",
            "BraveSoftware Brave-Origin-Nightly",
        ],
    },
];
