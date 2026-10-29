# rucert

[Русская версия](README.ru.md)

A console wizard for macOS and Windows that makes selected Chromium-based browsers trust the
Russian Trusted Root CA (issued by the Ministry of Digital Development,
https://www.gosuslugi.ru/crt) **only for a fixed list of domains**, without adding the
certificate to the system trust store.

## Why

Installing the Russian Trusted Root CA into the system trust store lets it vouch for _any_ site
in _every_ application. rucert limits that trust:

- only the browsers you pick;
- only the listed domains and their subdomains (for example, `gosuslugi.ru` covers
  `www.gosuslugi.ru` and `esia.gosuslugi.ru`);
- the system trust store (macOS keychain, Windows certificate store) stays untouched.

A certificate from this CA for any other domain is rejected, which protects against MITM via
this CA outside the allowed domains.

## How it works

The browser policy
[`CACertificatesWithConstraints`](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/cacertificateswithconstraints)
adds the root as a trust anchor with `permitted_dns_names`. The intermediates go to
[`CAHintCertificates`](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/cahintcertificates):
they are not trusted on their own and only help build the chain when a server does not send
its intermediate, so every chain still ends at the constrained root. Both policies are
mandatory-only:

- **macOS**: they are delivered through a configuration profile (`.mobileconfig`) with forced
  managed preferences. rucert generates the profile, opens it, and you approve the
  installation in System Settings. macOS does not allow installing profiles silently without
  MDM.
- **Windows**: they are written to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\<vendor>\<browser>`.
  The wizard itself runs without administrator rights; only the registry write runs elevated,
  after you confirm the Windows UAC prompt.

Supported browsers:

| Browser        | macOS preference domain    | Windows policy key                      |
| -------------- | -------------------------- | --------------------------------------- |
| Google Chrome  | `com.google.Chrome`        | `SOFTWARE\Policies\Google\Chrome`       |
| Microsoft Edge | `com.microsoft.Edge`       | `SOFTWARE\Policies\Microsoft\Edge`      |
| Brave          | `com.brave.Browser`        | `SOFTWARE\Policies\BraveSoftware\Brave` |
| Brave Origin   | `com.brave.Browser.origin` | `SOFTWARE\Policies\BraveSoftware\Brave` |

On Windows, Brave and the standalone Brave Origin read the same policy key, so the wizard shows
them as one entry, "Brave / Brave Origin".

The browser must be recent enough to support these policies. After installation they are
visible on `chrome://policy` / `edge://policy` / `brave://policy`.

Safari is not supported. It has no certificate store or policies of its own and trusts only
the macOS system store, so any certificate trusted there is trusted by every application.
That contradicts the goal of trusting the CA in selected browsers only.

Embedded certificates:

| Certificate                   | Role                                 | SHA-256                                                                                           |
| ----------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Russian Trusted Root CA       | trust anchor, limited to the domains | `D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31` |
| Russian Trusted Sub CA (2022) | chain-building hint                  | `BB:BD:E2:10:3E:79:0B:99:9E:C6:2B:D0:3C:F6:25:A5:A2:E7:C3:16:E1:0A:FE:6A:49:0E:ED:EA:D8:B3:FD:9B` |
| Russian Trusted Sub CA (2024) | chain-building hint                  | `21:55:78:50:36:C9:00:DB:B5:F1:BB:2A:15:69:C8:0C:55:59:5B:D6:BF:94:86:7A:29:BB:DD:BC:7D:88:A3:F2` |

## Installation

Download the archive for your system from
[Releases](https://github.com/dgavrilov/rucert/releases).

### macOS

Take `rucert-<version>-macos-arm64.tar.gz` for Apple Silicon or `-x86_64` for Intel. Unpack it
and remove the quarantine attribute (the binary is not notarized):

```sh
tar -xzf rucert-*-macos-*.tar.gz
xattr -d com.apple.quarantine rucert
./rucert
```

### Windows

Unpack `rucert-<version>-windows-x86_64.zip` (or `-arm64`) and run `rucert.exe` from a
console. The binary is not signed, so SmartScreen may warn about it: choose
**More info → Run anyway**.

Windows Terminal shows the full interface. In the classic console (`cmd.exe` or PowerShell
outside Windows Terminal) the wizard switches to ASCII symbols.

## Usage

On first launch the wizard asks for the interface language (English or Russian, preselected
from the system locale) and remembers it. Main menu:

- **Status**: detected browsers, policies currently applied, the embedded certificates.
- **Install or update**: pick browsers, review domains, then
  - macOS: approve the profile in System Settings → General → Device Management
    (macOS 13-14: Privacy & Security → Profiles);
  - Windows: confirm the UAC prompt.

  The wizard then verifies the policy is applied. Reinstalling replaces the previous policies,
  including removing them from browsers that are no longer selected; the selected browsers
  are remembered.

- **Manage domains**: browse and search all domains (typing filters the list), exclude
  domains of the main list, add or remove your own domains on top of it. Exclusions are kept
  by name, so they survive list updates; adding an excluded domain enables it again. At least
  one domain must remain. Long lists elsewhere in the wizard show only the first entries.
  Wildcards, top-level domains and IP addresses are rejected; internationalized names are
  converted to punycode. When you leave this menu with changes, the policies are applied again
  to the remembered browsers.
- **Check for domain list updates**: downloads `assets/constraints.json` from this repository,
  shows added and removed domains and applies the list only after confirmation; the policies
  are then applied again the same way.
- **Remove**:
  - macOS: runs `sudo profiles remove -identifier io.github.dgavrilov.rucert`; the profile can
    also be removed in System Settings;
  - Windows: removes rucert's policy values from the registry after the UAC prompt; other
    policies are left alone.
- **Change language**.

On macOS, if another profile sets the same policy for a browser (for example, one installed
manually earlier), remove it: macOS does not define which of two conflicting profiles wins.

Settings are stored in `~/Library/Application Support/rucert/settings.json` on macOS and in
`%APPDATA%\rucert\settings.json` on Windows.

## If the certificate was installed manually

The certificates do not need to be imported manually: the policies add them. A Russian
Trusted Root CA installed manually is trusted for every site, so the domain limits do not
apply to it. If it was installed earlier, for example following the instructions on
Gosuslugi, and you do not need it outside the browsers, you can remove it from:

- macOS keychain (Keychain Access, login and System keychains);
- Windows root store (Trusted Root Certification Authorities in `certmgr.msc` and
  `certlm.msc`);
- the browser's own certificate manager (`chrome://certificate-manager`, "Installed by you").

The wizard warns in **Status** and after installation when the certificate is trusted by the
system. Certificates imported into the browser's own manager cannot be detected, so check
those yourself.

## Domain list

[`assets/constraints.json`](assets/constraints.json) is embedded into the binary and served for updates:

```json
{ "version": 1, "domains": ["gosuslugi.ru", "..."] }
```

## Building

```sh
cargo test
cargo build --release
```

## License

BSD 3-Clause. See [LICENSE](LICENSE).
