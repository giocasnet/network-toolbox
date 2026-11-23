//! Windows clipboard for sensitive data (generated passwords).
//!
//! The text is copied together with the formats that exclude it from the clipboard
//! history (Win+V) and from cloud sync, as password managers do.
//! After `CLEAR_AFTER_SECS` seconds the clipboard is emptied, but only
//! if it still contains the password: in the meantime the Windows clipboard
//! sequence number must not have changed.

/// Seconds after which the clipboard is emptied.
pub const CLEAR_AFTER_SECS: u64 = 30;

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

/// Copies `text` to the clipboard; returns the clipboard sequence number
/// after the copy, to be passed to [`clear_if_unchanged`]. `owner` is the handle of the
/// app window (0 if it is not available: the copy is tried without an owner).
pub fn copy_secret(text: &str, owner: isize) -> crate::Result<u32> {
    #[cfg(windows)]
    {
        windows_impl::copy_secret(text, owner)
    }
    #[cfg(not(windows))]
    {
        let _ = (text, owner);
        Err(crate::t!(
            "Appunti protetti disponibili solo su Windows",
            "Protected clipboard is only available on Windows"
        )
        .into())
    }
}

/// Empties the clipboard if it has not changed since the copy. `true` = emptied.
pub fn clear_if_unchanged(seq: u32) -> crate::Result<bool> {
    #[cfg(windows)]
    {
        windows_impl::clear_if_unchanged(seq)
    }
    #[cfg(not(windows))]
    {
        let _ = seq;
        Ok(false)
    }
}
