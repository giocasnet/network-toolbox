//! Clipboard with the Win32 APIs (user32 / kernel32).

use crate::t;

use std::{iter, ptr, thread, time::Duration};
use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

const CF_UNICODETEXT: u32 = 13;

/// Formats that keep the text out of the history (Win+V), the cloud and
/// programs that monitor the clipboard. Documented by Microsoft in
/// "Clipboard Formats › Cloud Clipboard and Clipboard History Formats".
const PRIVACY_FORMATS: [&str; 3] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
];

/// Open clipboard; it is closed when leaving the scope.
struct Open;

impl Drop for Open {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}

fn open() -> crate::Result<Open> {
    // Another program may keep it open for a few milliseconds
    for _ in 0..20 {
        if unsafe { OpenClipboard(ptr::null_mut()) } != 0 {
            return Ok(Open);
        }
        thread::sleep(Duration::from_millis(15));
    }
    Err(t!(
        "Appunti in uso da un altro programma: riprova",
        "Clipboard in use by another program: try again"
    )
    .into())
}

fn set(format: u32, data: &[u8]) -> crate::Result<()> {
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, data.len().max(1));
        if h.is_null() {
            return Err(t!(
                "Memoria insufficiente per gli appunti",
                "Not enough memory for the clipboard"
            )
            .into());
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            GlobalFree(h);
            return Err(t!(
                "Memoria insufficiente per gli appunti",
                "Not enough memory for the clipboard"
            )
            .into());
        }
        ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
        GlobalUnlock(h);
        // If it succeeds, the memory passes to the system
        if SetClipboardData(format, h as HANDLE).is_null() {
            GlobalFree(h);
            return Err(t!(
                "Impossibile scrivere negli appunti",
                "Cannot write to the clipboard"
            )
            .into());
        }
    }
    Ok(())
}

fn register(name: &str) -> u32 {
    let w: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
    unsafe { RegisterClipboardFormatW(w.as_ptr()) }
}

pub fn copy_secret(text: &str) -> crate::Result<u32> {
    let utf16: Vec<u8> = text
        .encode_utf16()
        .chain(iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    {
        let _open = open()?;
        if unsafe { EmptyClipboard() } == 0 {
            return Err(t!(
                "Impossibile svuotare gli appunti",
                "Cannot empty the clipboard"
            )
            .into());
        }
        set(CF_UNICODETEXT, &utf16)?;
        // DWORD 0 = "do not include"; if a format is not available carry on
        for name in PRIVACY_FORMATS {
            let f = register(name);
            if f != 0 {
                let _ = set(f, &0u32.to_le_bytes());
            }
        }
    }
    Ok(unsafe { GetClipboardSequenceNumber() })
}

pub fn clear_if_unchanged(seq: u32) -> crate::Result<bool> {
    if unsafe { GetClipboardSequenceNumber() } != seq {
        return Ok(false);
    }
    let _open = open()?;
    if unsafe { GetClipboardSequenceNumber() } != seq {
        return Ok(false);
    }
    Ok(unsafe { EmptyClipboard() } != 0)
}
