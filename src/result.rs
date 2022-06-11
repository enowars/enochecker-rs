use std::{fmt::Debug, io};

use tracing::warn;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckerError {
    Mumble(&'static str),
    Offline(&'static str),
    InternalError(&'static str),
}

pub type CheckerResult<T> = Result<T, CheckerError>;

// FromUTF8Error auto into is disabled
// impl From<FromUtf8Error> for CheckerError {
//     fn from(e: FromUtf8Error) -> Self {
//         warn!("UTF8 decoding failed {}", e);
//         return CheckerError::Mumble("Client returned invalid UTF8");
//     }
// }

pub trait CheckerFromIOError {
    fn into_checker_error(self, msg: &'static str) -> CheckerError;
}

impl CheckerFromIOError for io::Error {
    fn into_checker_error(self, msg: &'static str) -> CheckerError {
        match self.kind() {
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset => {
                warn!("Converting io::Error to CheckerError OFFLINE -- {:?}", self);
                CheckerError::Offline(msg)
            }
            io::ErrorKind::UnexpectedEof => {
                warn!("Converting io::Error to CheckerError MUMBLE -- {:?}", self);
                CheckerError::Mumble(msg)
            }
            _ => {
                warn!(
                    "Converting io::Error to CheckerError INTERNAL_ERROR -- {:?}",
                    self
                );
                CheckerError::InternalError(msg)
            }
        }
    }
}

pub trait CheckerfromIOResult<T> {
    fn into_checker_result(self, msg: &'static str) -> CheckerResult<T>;
}

impl<T> CheckerfromIOResult<T> for io::Result<T> {
    fn into_checker_result(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| e.into_checker_error(msg))
    }
}

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
where
    E: IntoCheckerError,
{
    fn into_mumble(self, msg: &'static str) -> CheckerResult<T>;
    fn into_offline(self, msg: &'static str) -> CheckerResult<T>;
    fn into_error(self, msg: &'static str) -> CheckerResult<T>;
}

impl<T, E> IntoCheckerResult<T, E> for Result<T, E>
where
    E: Debug,
{
    fn into_mumble(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| e.into_mumble_error(msg))
    }

    fn into_offline(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| e.into_offline_error(msg))
    }

    fn into_error(self, msg: &'static str) -> CheckerResult<T> {
        self.map_err(|e| e.into_internal_error(msg))
    }
}

impl<T> IntoCheckerResult<T, Option<()>> for Option<T>
{
    fn into_mumble(self, msg: &'static str) -> CheckerResult<T> {
        self.ok_or(None).map_err(|e:Option<()>| e.into_mumble_error(msg))
    }

    fn into_offline(self, msg: &'static str) -> CheckerResult<T> {
        self.ok_or(None).map_err(|e:Option<()>| e.into_offline_error(msg))
    }

    fn into_error(self, msg: &'static str) -> CheckerResult<T> {
        self.ok_or(None).map_err(|e:Option<()>| e.into_internal_error(msg))
    }
}
