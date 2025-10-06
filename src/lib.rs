// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Dynamic [`rustls`] TLS configuration backed by [`rustls-spiffe`] and [`rustls-config-stream`].
//! Effortlessly hot-swap new X509-SVIDs and Trust Bundles
//!
//! Provides [`SpiffeClientConfigStream`] and [`SpiffeServerConfigStream`] for
//! use with [`ClientConfigProvider`] and [`ServerConfigProvider`]

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

mod trust_domain_store;
pub(crate) use trust_domain_store::TrustDomainStore;
