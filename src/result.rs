use std::fmt::Debug;

use tracing::warn;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckerError {
    Mumble(&'static str),
    Offline(&'static str),
    InternalError(&'static str),
}

// FromUTF8Error auto into is disabled
// impl From<FromUtf8Error> for CheckerError {
//     fn from(e: FromUtf8Error) -> Self {
//         warn!("UTF8 decoding failed {}", e);
//         return CheckerError::Mumble("Client returned invalid UTF8");
//     }
// }

pub type CheckerResult<T> = Result<T, CheckerError>;

pub trait IntoCheckerError {
    fn into_mumble_error(self, msg: &'static str) -> CheckerError;
    fn into_offline_error(self, msg: &'static str) -> CheckerError;
    fn into_internal_error(self, msg: &'static str) -> CheckerError;
}


impl<T: Debug> IntoCheckerError for T {
    fn into_mumble_error(self, msg: &'static str) -> CheckerError {
        warn!("Interpreting as MUMBLE -- {:?}", self);
        CheckerError::Mumble(msg)
    }

    fn into_offline_error(self, msg: &'static str) -> CheckerError {
        warn!("Interpreting as OFFLINE -- {:?}", self);
        CheckerError::Offline(msg)
    }

    fn into_internal_error(self, msg: &'static str) -> CheckerError {
        warn!("Interpreting as INTERNAL_ERROR -- {:?}", self);
        CheckerError::InternalError(msg)
    }
}

pub trait IntoCheckerResult<T, E> 
where E:Debug {
    fn into_mumble(self, msg: &'static str) -> CheckerResult<T>;
    fn into_offline(self, msg: &'static str) -> CheckerResult<T>;
    fn into_error(self, msg: &'static str) -> CheckerResult<T>;
}

impl<T,E> IntoCheckerResult<T,E> for Result<T,E> 
where E:Debug {
    fn into_mumble(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| {
            e.into_mumble_error(msg)
        })
    }

    fn into_offline(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| {
            e.into_offline_error(msg)
        })
    }

    fn into_error(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| {
            e.into_internal_error(msg)
        })
    }
}

