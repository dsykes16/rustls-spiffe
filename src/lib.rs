// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#![doc = include_str!("../README.md")]
#![forbid(rust_2018_idioms)]
#![forbid(missing_docs, unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::nursery,
    clippy::dbg_macro,
    clippy::todo
)]

#[cfg(feature = "config-stream")]
mod client_stream;
#[cfg(feature = "config-stream")]
mod server_stream;

#[cfg(feature = "config-stream")]
pub use client_stream::{ClientConfigProvider, SpiffeClientConfigStream};
#[cfg(feature = "config-stream")]
pub use server_stream::{ServerConfigProvider, SpiffeServerConfigStream};
