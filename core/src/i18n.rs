//! Interface language of the messages produced by the backend.
//!
//! The language is a process-wide setting: the UI sends it with the `set_lang`
//! command at startup (and after every change), and every user-facing message
//! (errors, check names and details, notes) picks its text at the moment it is
//! built. Italian is the default.
//!
//! Use [`t!`] for fixed texts and [`tf!`] for texts with placeholders:
//!
//! ```ignore
//! Err(t!("Timeout: da 100 a 5000 ms", "Timeout: 100 to 5000 ms").to_string())
//! Err(tf!("Porta {p} chiusa", "Port {p} closed"))
//! ```
//!
//! Machine codes that the UI compares against (statuses such as `ok`/`warn`,
//! strengths, protocol names) must **not** be translated: only text shown to
//! the user.
//!
//! In tests the language can be forced for the current thread only with
//! [`scoped`], so tests running in parallel never see each other's setting.

use std::cell::Cell;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    It,
    En,
}

static LANG: AtomicU8 = AtomicU8::new(0);

thread_local! {
    static OVERRIDE: Cell<Option<Lang>> = const { Cell::new(None) };
}

/// Sets the process-wide language.
pub fn set(lang: Lang) {
    LANG.store(if lang == Lang::En { 1 } else { 0 }, Ordering::Relaxed);
}

/// Language code → [`Lang`] (`"en"` = English, anything else = Italian).
pub fn parse(code: &str) -> Lang {
    if code.trim().to_ascii_lowercase().starts_with("en") {
        Lang::En
    } else {
        Lang::It
    }
}

/// Current language (thread override first, then the process-wide setting).
pub fn get() -> Lang {
    if let Some(l) = OVERRIDE.with(|o| o.get()) {
        return l;
    }
    if LANG.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::It
    }
}

pub fn is_en() -> bool {
    get() == Lang::En
}

/// Restores the thread override when dropped.
pub struct Scoped(Option<Lang>);

impl Drop for Scoped {
    fn drop(&mut self) {
        OVERRIDE.with(|o| o.set(self.0));
    }
}

/// Forces `lang` on the current thread until the guard is dropped (tests).
#[must_use]
pub fn scoped(lang: Lang) -> Scoped {
    let prev = OVERRIDE.with(|o| o.replace(Some(lang)));
    Scoped(prev)
}

/// Fixed text in the two languages: `t!("italiano", "english")` → `&'static str`
/// (any expression of the same type works, e.g. two `String`s are not allowed:
/// use [`tf!`] for those).
#[macro_export]
macro_rules! t {
    ($it:expr, $en:expr) => {
        if $crate::i18n::is_en() {
            $en
        } else {
            $it
        }
    };
}

/// Text with placeholders in the two languages, like `format!`:
/// `tf!("Porta {p} chiusa", "Port {p} closed")` or with arguments
/// `tf!("{} host", "{} hosts", n)`. Returns a `String`.
#[macro_export]
macro_rules! tf {
    ($it:literal, $en:literal $(, $($args:tt)*)?) => {
        if $crate::i18n::is_en() {
            format!($en $(, $($args)*)?)
        } else {
            format!($it $(, $($args)*)?)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_italian_and_scoped_overrides() {
        assert_eq!(t!("ciao", "hello"), "ciao");
        {
            let _g = scoped(Lang::En);
            assert_eq!(t!("ciao", "hello"), "hello");
            let p = 80;
            assert_eq!(tf!("Porta {p}", "Port {p}"), "Port 80");
            assert_eq!(tf!("{} host", "{} hosts", 3), "3 hosts");
        }
        assert_eq!(t!("ciao", "hello"), "ciao");
        assert_eq!(tf!("{} host", "{} hosts", 3), "3 host");
    }

    #[test]
    fn language_codes() {
        assert_eq!(parse("en"), Lang::En);
        assert_eq!(parse("EN-gb"), Lang::En);
        assert_eq!(parse("it"), Lang::It);
        assert_eq!(parse(""), Lang::It);
    }
}
