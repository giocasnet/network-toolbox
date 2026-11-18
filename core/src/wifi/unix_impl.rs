//! Outside Windows there are no equivalent Wi-Fi APIs: the section shows
//! "not available". It only exists to build and test the rest on Linux.

use super::{BackendError, Notice, RawAdapter, RawSample, RawScan, Source};

pub fn adapters() -> Result<Vec<RawAdapter>, BackendError> {
    Err(BackendError::Unsupported)
}

pub fn scan(_id: &str, _fresh: bool) -> Result<RawScan, BackendError> {
    Err(BackendError::Unsupported)
}

pub struct Watch;

impl Watch {
    pub fn open(_id: &str) -> Result<Self, BackendError> {
        Err(BackendError::Unsupported)
    }
}

impl Source for Watch {
    fn sample(&mut self) -> Result<RawSample, BackendError> {
        Err(BackendError::Unsupported)
    }
    fn notices(&mut self) -> Vec<Notice> {
        Vec::new()
    }
    fn channel_of(&mut self, _bssid: &[u8; 6]) -> Option<u16> {
        None
    }
}
