//! Interactive wizard built on cliclack.

use std::collections::BTreeSet;
use std::error::Error;
use std::io;

use cliclack::{Theme, ThemeState, confirm, input, log, multiselect, note, select, spinner};
use console::{Emoji, Style, style};
use rust_i18n::t;

use crate::browsers::{BROWSERS, Browser};
use crate::constraints::{self, UPDATE_URL};
use crate::domains;
#[cfg(target_os = "macos")]
use crate::macos as os;
use crate::policy::{INTERMEDIATES, ROOT_CA};
use crate::settings::{Language, Rejected, Settings};
#[cfg(windows)]
use crate::windows as os;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

/// Message whose wording depends on the platform: `macos.<key>` or `windows.<key>`.
macro_rules! os_t {
    ($key:literal $($args:tt)*) => {
        if cfg!(windows) {
            t!(concat!("windows.", $key) $($args)*)
        } else {
            t!(concat!("macos.", $key) $($args)*)
        }
    };
}

// Glyphs with ASCII fallbacks for consoles without Unicode symbols (classic Windows
// console); `console` picks the fallback the same way cliclack does.
const BAR: Emoji = Emoji("│", "|");
const BULLET: Emoji = Emoji("•", "*");
const ARROW: Emoji = Emoji("→", "->");

/// Default cliclack theme with localized Yes/No labels and readable (non-dimmed)
/// note bodies and submitted answers.
struct WizardTheme;

impl Theme for WizardTheme {
    /// The default dims submitted text, which also greys out every note body.
    fn input_style(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Cancel => Style::new().dim().strikethrough(),
            _ => Style::new(),
        }
    }

    fn format_confirm(&self, state: &ThemeState, confirm: bool) -> String {
        let yes = self.radio_item(state, confirm, &t!("common.yes"), "");
        let no = self.radio_item(state, !confirm, &t!("common.no"), "");
        let divider = match state {
            ThemeState::Active => self.placeholder_style(state).apply_to(" / ").to_string(),
            _ => String::new(),
        };
        format!(
            "{}  {yes}{divider}{no}\n",
            self.bar_color(state).apply_to(BAR)
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Status,
    Install,
    Domains,
    Update,
    Remove,
    Language,
    Exit,
}

pub fn run() -> Result {
    cliclack::set_theme(WizardTheme);
    let (mut settings, rejected, load_error) = match Settings::load() {
        Ok((settings, rejected)) => (settings, rejected, None),
        Err(e) => (Settings::default(), Rejected::default(), Some(e)),
    };

    let language = match settings.language {
        Some(language) => language,
        None => {
            let language = choose_language(Language::detect())?;
            settings.language = Some(language);
            save(&settings);
            language
        }
    };
    rust_i18n::set_locale(language.code());
    cliclack::intro(style(format!(" {} ", t!("app.title"))).on_cyan().black())?;

    // Reported only now, so the messages use the chosen language.
    if let Some(e) = load_error {
        log::warning(t!("common.settings_load_failed", error = e))?;
    }
    if !rejected.custom_domains.is_empty() {
        log::warning(t!(
            "common.settings_rejected_domains",
            domains = rejected.custom_domains.join(", ")
        ))?;
    }
    if rejected.downloaded_list {
        log::warning(t!("common.settings_rejected_list"))?;
    }
    if !rejected.is_empty() {
        save(&settings);
    }

    loop {
        let action = select(t!("menu.prompt"))
            .item(Action::Status, t!("menu.status"), t!("menu.status_hint"))
            .item(
                Action::Install,
                os_t!("menu_install"),
                t!("menu.install_hint"),
            )
            .item(Action::Domains, t!("menu.domains"), t!("menu.domains_hint"))
            .item(Action::Update, t!("menu.update"), t!("menu.update_hint"))
            .item(Action::Remove, os_t!("menu_remove"), t!("menu.remove_hint"))
            .item(Action::Language, t!("menu.language"), "")
            .item(Action::Exit, t!("menu.exit"), "")
            .interact();
        let action = match action {
            Ok(action) => action,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Action::Exit,
            Err(e) => return Err(e.into()),
        };

        let outcome = match action {
            Action::Status => status(&settings),
            Action::Install => install(&mut settings),
            Action::Domains => manage_domains(&mut settings),
            Action::Update => update(&mut settings),
            Action::Remove => remove(&mut settings),
            Action::Language => change_language(&mut settings),
            Action::Exit => break,
        };
        if let Err(e) = outcome {
            if is_interrupted(e.as_ref()) {
                log::remark(t!("common.cancelled"))?;
            } else {
                log::error(t!("common.error", error = e))?;
            }
        }
    }

    cliclack::outro(t!("app.bye"))?;
    Ok(())
}

fn is_interrupted(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::Interrupted)
}

fn save(settings: &Settings) {
    if let Err(e) = settings.save() {
        let _ = log::warning(t!("common.settings_save_failed", error = e));
    }
}

/// Shown before any locale is chosen, so labels are in both languages.
fn choose_language(initial: Language) -> Result<Language> {
    Ok(select(t!("language.prompt"))
        .item(Language::Ru, "Русский", "")
        .item(Language::En, "English", "")
        .initial_value(initial)
        .interact()?)
}

fn change_language(settings: &mut Settings) -> Result {
    let language = choose_language(settings.language.unwrap_or_else(Language::detect))?;
    settings.language = Some(language);
    rust_i18n::set_locale(language.code());
    save(settings);
    Ok(())
}

fn heading(text: impl std::fmt::Display) -> String {
    style(text).bold().to_string()
}

fn domain_list(domains: &[String]) -> String {
    marked_domain_list(domains, &style(BULLET).cyan())
}

fn marked_domain_list(domains: &[String], marker: &impl std::fmt::Display) -> String {
    if domains.is_empty() {
        return format!("  {}", style(t!("common.none")).dim());
    }
    domains
        .iter()
        .map(|domain| format!("  {marker} {}", domains::display(domain)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn status(settings: &Settings) -> Result {
    let installed = os::installed_browsers();
    let curated = settings.curated();
    let browsers = BROWSERS
        .iter()
        .map(|browser| {
            if !installed.contains(&browser) {
                style(t!("status.browser_missing", browser = browser.name)).dim()
            } else if let Some(applied) = os::applied(browser) {
                let count = applied.domains.len();
                if applied.hints_complete {
                    style(t!(
                        "status.browser_applied",
                        browser = browser.name,
                        count = count
                    ))
                    .green()
                } else {
                    style(os_t!(
                        "applied_no_hints",
                        browser = browser.name,
                        count = count
                    ))
                    .yellow()
                }
            } else {
                style(t!("status.browser_not_applied", browser = browser.name))
            }
        })
        .map(|line| format!("  {} {line}", style(BULLET).cyan()))
        .collect::<Vec<_>>()
        .join("\n");
    let certificates = std::iter::once((&ROOT_CA, t!("status.cert_root")))
        .chain(
            INTERMEDIATES
                .iter()
                .map(|cert| (cert, t!("status.cert_hint"))),
        )
        .map(|(cert, role)| {
            format!(
                "  {} {} - {role}\n    {}",
                style(BULLET).cyan(),
                style(cert.name).bold(),
                style(format!("SHA-256: {}", cert.sha256())).dim()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        "{}\n{}\n\n{}\n\n{}\n{}",
        heading(t!("status.certificates")),
        certificates,
        t!(
            "status.lists",
            version = curated.version,
            count = curated.domains.len(),
            custom = settings.custom_domains.len()
        ),
        heading(t!("status.browsers")),
        browsers
    );
    note(t!("status.title"), body)?;
    warn_system_trust()
}

/// The policies only add constrained trust: a root CA trusted by the OS itself is still
/// trusted for every site, so the user has to remove it there.
fn warn_system_trust() -> Result {
    if os::root_trusted_system_wide() {
        log::warning(os_t!("system_trust"))?;
    }
    Ok(())
}

fn install(settings: &mut Settings) -> Result {
    let installed = os::installed_browsers();
    let mut prompt = multiselect(t!("install.select_browsers")).required(true);
    for (index, browser) in BROWSERS.iter().enumerate() {
        let hint = if installed.contains(&browser) {
            t!("install.found")
        } else {
            t!("install.not_found")
        };
        prompt = prompt.item(index, browser.name, hint);
    }
    // Last selection wins; on first install, offer what is installed.
    let preselected = BROWSERS
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            if settings.profile_browsers.is_empty() {
                installed.contains(b)
            } else {
                settings.profile_browsers.iter().any(|id| id == b.id)
            }
        })
        .map(|(i, _)| i)
        .collect();
    let selected: Vec<&Browser> = prompt
        .initial_values(preselected)
        .interact()?
        .into_iter()
        .map(|i| &BROWSERS[i])
        .collect();

    let domains = settings.effective_domains();
    note(
        t!("install.domains_title", count = domains.len()),
        domain_list(&domains),
    )?;
    if !confirm(os_t!("install_confirm"))
        .initial_value(true)
        .interact()?
    {
        return Err(io::Error::from(io::ErrorKind::Interrupted).into());
    }

    deploy(settings, &selected, &domains)
}

/// Re-applies the domain list to the browsers chosen at the last installation.
fn reapply(settings: &mut Settings) -> Result {
    let selected: Vec<&Browser> = BROWSERS
        .iter()
        .filter(|b| settings.profile_browsers.iter().any(|id| id == b.id))
        .collect();
    if selected.is_empty() {
        log::info(os_t!("not_installed"))?;
        return Ok(());
    }
    let domains = settings.effective_domains();
    log::step(os_t!("updating", count = domains.len()))?;
    deploy(settings, &selected, &domains)
}

/// Hands the policies to the OS, remembers the browsers, then verifies what was applied.
fn deploy(settings: &mut Settings, selected: &[&Browser], domains: &[String]) -> Result {
    let verify = hand_over(selected, domains)?;
    settings.profile_browsers = selected.iter().map(|b| b.id.to_owned()).collect();
    save(settings);
    if !verify {
        return Ok(());
    }

    let expected: BTreeSet<&String> = domains.iter().collect();
    for browser in selected {
        match os::applied(browser) {
            Some(applied)
                if applied.hints_complete
                    && applied.domains.iter().collect::<BTreeSet<_>>() == expected =>
            {
                log::success(t!(
                    "install.verified",
                    browser = browser.name,
                    count = applied.domains.len()
                ))?
            }
            Some(_) => log::warning(os_t!("mismatch", browser = browser.name))?,
            None => log::error(os_t!("missing", browser = browser.name))?,
        }
    }
    let urls: BTreeSet<&str> = selected.iter().map(|b| b.policy_url).collect();
    log::info(t!(
        "install.reload",
        urls = urls.into_iter().collect::<Vec<_>>().join(", ")
    ))?;
    warn_system_trust()
}

/// Generates the profile and walks the user through approving it. Returns whether the
/// user reports it installed, i.e. whether verification makes sense now.
#[cfg(target_os = "macos")]
fn hand_over(selected: &[&Browser], domains: &[String]) -> Result<bool> {
    let path = os::write_and_open(&os::build(selected, domains), &Settings::dir()?)?;
    log::info(t!("macos.saved", path = path.display()))?;
    if os::open_profiles_pane().is_err() {
        log::warning(t!("macos.pane_failed"))?;
    }
    note(t!("macos.instructions_title"), t!("macos.instructions"))?;
    Ok(confirm(t!("macos.wait")).initial_value(true).interact()?)
}

/// Writes the registry policies through UAC; a declined prompt cancels the step. The
/// elevated process takes the domains from the saved settings, which `domains` was
/// computed from, so they are not passed here.
#[cfg(windows)]
fn hand_over(selected: &[&Browser], _domains: &[String]) -> Result<bool> {
    log::step(t!("windows.writing"))?;
    os::apply(selected)?;
    Ok(true)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DomainAction {
    Add,
    Remove,
    Back,
}

/// Changes are batched: the policies are applied again once, when leaving the menu.
fn manage_domains(settings: &mut Settings) -> Result {
    let before = settings.effective_domains();
    loop {
        let curated = settings.curated();
        note(
            t!("domains.title"),
            format!(
                "{}\n{}\n\n{}\n{}",
                heading(t!("domains.curated", version = curated.version)),
                domain_list(&curated.domains),
                heading(t!("domains.custom")),
                domain_list(&settings.custom_domains),
            ),
        )?;

        let mut prompt =
            select(t!("domains.prompt")).item(DomainAction::Add, t!("domains.add"), "");
        if !settings.custom_domains.is_empty() {
            prompt = prompt.item(DomainAction::Remove, t!("domains.remove"), "");
        }
        let action = match prompt
            .item(DomainAction::Back, t!("domains.back"), "")
            .interact()
        {
            Ok(action) => action,
            // Esc leaves the menu like "Back", so saved changes still get applied.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => DomainAction::Back,
            Err(e) => return Err(e.into()),
        };
        let outcome = match action {
            DomainAction::Add => add_domain(settings),
            DomainAction::Remove => remove_domains(settings),
            DomainAction::Back => break,
        };
        match outcome {
            Err(e) if is_interrupted(e.as_ref()) => log::remark(t!("common.cancelled"))?,
            Err(e) => log::error(t!("common.error", error = e))?,
            Ok(()) => {}
        }
    }
    if settings.effective_domains() != before {
        reapply(settings)?;
    }
    Ok(())
}

fn add_domain(settings: &mut Settings) -> Result {
    let raw: String = input(t!("domains.add_prompt"))
        .placeholder(&t!("domains.add_placeholder"))
        .validate(|value: &String| {
            domains::normalize(value)
                .map(drop)
                .map_err(|e| t!(e.message_key()).into_owned())
        })
        .interact()?;
    let domain = domains::normalize(&raw)?;
    match domains::covered_by(&domain, &settings.effective_domains()) {
        Some(entry) if *entry == domain => {
            log::warning(t!("domains.exists", domain = domains::display(&domain)))?;
            return Ok(());
        }
        Some(parent) => {
            log::warning(t!(
                "domains.covered",
                domain = domains::display(&domain),
                parent = domains::display(parent)
            ))?;
            return Ok(());
        }
        None => {}
    }
    settings.custom_domains.push(domain.clone());
    settings.custom_domains.sort();
    save(settings);
    log::success(t!("domains.added", domain = domains::display(&domain)))?;
    Ok(())
}

fn remove_domains(settings: &mut Settings) -> Result {
    let mut prompt = multiselect(t!("domains.remove_prompt")).required(false);
    for domain in &settings.custom_domains {
        prompt = prompt.item(domain.clone(), domains::display(domain), "");
    }
    let to_remove = prompt.interact()?;
    if to_remove.is_empty() {
        return Ok(());
    }
    settings.custom_domains.retain(|d| !to_remove.contains(d));
    save(settings);
    log::success(t!("domains.removed", count = to_remove.len()))?;
    Ok(())
}

fn update(settings: &mut Settings) -> Result {
    let before = settings.effective_domains();
    let current = settings.curated();
    let progress = spinner();
    progress.start(t!("update.checking", url = UPDATE_URL));
    let remote = match constraints::fetch() {
        Ok(remote) => {
            progress.stop(t!("update.checking", url = UPDATE_URL));
            remote
        }
        Err(e) => {
            progress.error(t!("update.failed"));
            return Err(e);
        }
    };

    if remote.version <= current.version {
        log::success(t!("update.up_to_date", version = current.version))?;
        return Ok(());
    }

    let diff = constraints::diff(&current.domains, &remote.domains);
    note(
        t!(
            "update.available",
            old = current.version,
            new = remote.version,
            arrow = ARROW
        ),
        format!(
            "{}\n{}\n\n{}\n{}",
            heading(t!("update.added")),
            marked_domain_list(&diff.added, &style("+").green().bold()),
            heading(t!("update.removed")),
            marked_domain_list(&diff.removed, &style("-").red().bold()),
        ),
    )?;
    if !confirm(t!("update.confirm"))
        .initial_value(false)
        .interact()?
    {
        return Err(io::Error::from(io::ErrorKind::Interrupted).into());
    }
    let version = remote.version;
    settings.downloaded = Some(remote);
    save(settings);
    log::success(t!("update.applied", version = version))?;
    if settings.effective_domains() != before {
        reapply(settings)?;
    }
    Ok(())
}

fn remove(settings: &mut Settings) -> Result {
    if !confirm(os_t!("remove_confirm"))
        .initial_value(false)
        .interact()?
    {
        return Err(io::Error::from(io::ErrorKind::Interrupted).into());
    }
    #[cfg(target_os = "macos")]
    log::step(t!("macos.remove_running", id = os::PROFILE_ID))?;
    #[cfg(windows)]
    log::step(t!("windows.remove_running"))?;
    match os::remove() {
        Ok(()) => {
            // Nothing to re-apply domain changes to until the next installation.
            settings.profile_browsers.clear();
            save(settings);
            log::success(os_t!("remove_done"))?
        }
        Err(e) if is_interrupted(&e) => log::remark(t!("common.cancelled"))?,
        Err(e) => log::error(os_t!("remove_failed", error = e))?,
    }
    Ok(())
}
