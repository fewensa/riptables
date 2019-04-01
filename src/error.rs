use std::{convert, error, fmt, io, num};
use std::error::Error;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum RIPTError {
  Io(io::Error),
  Nix(nix::Error),
  Parse(num::ParseIntError),
  Analysis(RIPTAnalysisError),
  Stderr(String),
  Other(&'static str),
}

/// Defines the Result type of iptables crate
pub type RIPTResult<T> = Result<T, RIPTError>;

impl fmt::Display for RIPTError {
  fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
    match *self {
      RIPTError::Io(ref err) => write!(f, "{}", err),
      RIPTError::Nix(ref err) => write!(f, "{}", err),
      RIPTError::Parse(ref err) => write!(f, "{}", err),
      RIPTError::Analysis(ref err) => write!(f, "{}", err),
      RIPTError::Stderr(ref message) => write!(f, "{}", message),
      RIPTError::Other(ref message) => write!(f, "{}", message)
    }
  }
}

impl error::Error for RIPTError {
  fn description(&self) -> &str {
    match *self {
      RIPTError::Io(ref err) => err.description(),
      RIPTError::Nix(ref err) => err.description(),
      RIPTError::Parse(ref err) => err.description(),
      RIPTError::Analysis(ref err) => err.description(),
      RIPTError::Stderr(ref message) => message,
      RIPTError::Other(ref message) => message,
    }
  }

  fn cause(&self) -> Option<&error::Error> {
    match *self {
      RIPTError::Io(ref err) => Some(err),
      RIPTError::Nix(ref err) => Some(err),
      RIPTError::Parse(ref err) => Some(err),
      RIPTError::Analysis(ref err) => Some(err),
      _ => Some(self),
    }
  }
}

impl convert::From<io::Error> for RIPTError {
  fn from(err: io::Error) -> Self {
    RIPTError::Io(err)
  }
}

impl convert::From<nix::Error> for RIPTError {
  fn from(err: nix::Error) -> Self {
    RIPTError::Nix(err)
  }
}

impl convert::From<num::ParseIntError> for RIPTError {
  fn from(err: num::ParseIntError) -> Self {
    RIPTError::Parse(err)
  }
}

impl convert::From<&'static str> for RIPTError {
  fn from(err: &'static str) -> Self {
    RIPTError::Other(err)
  }
}

impl convert::From<RIPTAnalysisError> for RIPTError {
  fn from(err: RIPTAnalysisError) -> Self {
    RIPTError::Analysis(err)
  }
}

#[derive(Debug)]
pub enum RIPTAnalysisError {
  FromUtf8Error(FromUtf8Error),
  UnexpectedOutput(String),
}

pub type RIPTAnalysisResult<T> = Result<T, RIPTAnalysisError>;


impl fmt::Display for RIPTAnalysisError {
  fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
    match *self {
      RIPTAnalysisError::FromUtf8Error(ref err) => write!(f, "{}", err),
      RIPTAnalysisError::UnexpectedOutput(ref message) => write!(f, "{}", message),
    }
  }
}

impl error::Error for RIPTAnalysisError {
  fn description(&self) -> &str {
    match *self {
      RIPTAnalysisError::FromUtf8Error(ref err) => err.description(),
      RIPTAnalysisError::UnexpectedOutput(ref message) => message,
    }
  }

  fn cause(&self) -> Option<&error::Error> {
    match *self {
      RIPTAnalysisError::FromUtf8Error(ref err) => Some(err),
      _ => Some(self),
    }
  }
}

impl convert::From<FromUtf8Error> for RIPTAnalysisError {
  fn from(err: FromUtf8Error) -> Self {
    RIPTAnalysisError::FromUtf8Error(err)
  }
}

