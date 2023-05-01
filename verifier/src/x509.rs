// Copyright (c) 2023 The MobileCoin Foundation

// TODO: Remove dead_code exception once this is connected up to the rest of the codebase
#![allow(dead_code)]
mod certs;
mod error;

pub use error::Error;
pub type Result<T> = core::result::Result<T, Error>;
