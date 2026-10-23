// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Dynamic [`rustls`] TLS configuration backed by the [SPIFFE Workload API][spiffe]
//! and [`rustls-config-stream`]. Effortlessly hot-swap new X509-SVIDs and Trust
//! Bundles as they rotate, without restarting your service.
//!
//! Provides [`SpiffeClientConfigStream`] and [`SpiffeServerConfigStream`] for
//! use with [`ClientConfigProvider`] and [`ServerConfigProvider`].
//!
//! ## Installation
//!
//! ```sh
//! cargo add rustls-spiffe
//! ```
//!
//! The providers connect to the Workload API at the address in the
//! `SPIFFE_ENDPOINT_SOCKET` environment variable (e.g.
//! `unix:///tmp/spire-agent/public/api.sock`).
//!
//! ## Example
//!
//! An mTLS server that only accepts clients presenting an X509-SVID from the
//! `example.org` trust domain and greets them by SPIFFE ID, plus a client that
//! connects to it. In a real deployment these would be separate workloads; they
//! share a process here so the example runs as-is.
//!
//! ```
//! use rustls_spiffe::{
//!     ClientConfigProvider, ServerConfigProvider, SpiffeClientConfigStream,
//!     SpiffeServerConfigStream, extract_leaf_cert, extract_spiffe_id,
//! };
//! use tokio::{
//!     io::{AsyncReadExt, AsyncWriteExt},
//!     net::{TcpListener, TcpStream},
//! };
//! use tokio_rustls::{TlsAcceptor, TlsConnector};
//!
//! type Error = Box<dyn std::error::Error + Send + Sync>;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     let listener = TcpListener::bind("127.0.0.1:8443").await?;
//!     tokio::spawn(serve(listener));
//!
//!     let greeting = greet().await?;
//!     print!("{greeting}");
//! #   assert!(greeting.starts_with("hello, spiffe://example.org/"), "{greeting:?}");
//!     Ok(())
//! }
//!
//! /// Accept clients from `example.org` and greet them by SPIFFE ID.
//! async fn serve(listener: TcpListener) -> Result<(), Error> {
//!     let builder = SpiffeServerConfigStream::builder(vec!["example.org".try_into()?]);
//!
//!     // Waits for the first SVID, then keeps the config current in the background.
//!     let provider = ServerConfigProvider::start(builder).await?;
//!
//!     loop {
//!         let (tcp, _) = listener.accept().await?;
//!
//!         // Fetch the config per connection so every handshake uses the latest
//!         // SVID and trust bundle.
//!         let acceptor = TlsAcceptor::from(provider.get_config());
//!
//!         tokio::spawn(async move {
//!             let Ok(mut tls) = acceptor.accept(tcp).await else {
//!                 return;
//!             };
//!             if let Some(id) = extract_spiffe_id(extract_leaf_cert(&tls)) {
//!                 let _ = tls.write_all(format!("hello, {id}\n").as_bytes()).await;
//!             }
//!             let _ = tls.shutdown().await;
//!         });
//!     }
//! }
//!
//! /// Connect to a server from `example.org` and return its greeting.
//! async fn greet() -> Result<String, Error> {
//!     let builder = SpiffeClientConfigStream::builder(vec!["example.org".try_into()?]);
//!     let provider = ClientConfigProvider::start(builder).await?;
//!
//!     // As on the server, fetch the config for each new connection.
//!     let connector = TlsConnector::from(provider.get_config());
//!     let tcp = TcpStream::connect("localhost:8443").await?;
//!     let mut tls = connector.connect("localhost".try_into()?, tcp).await?;
//!
//!     let mut greeting = String::new();
//!     tls.read_to_string(&mut greeting).await?;
//!     Ok(greeting)
//! }
//! ```
//!
//! The server verifies that client certificates chain to a configured trust
//! domain, but does not restrict *which* workloads in that trust domain may
//! connect. Use [`extract_spiffe_id`] to authorize individual SPIFFE IDs.
//!
//! The client performs standard hostname verification, so the server's SVID
//! must carry a DNS SAN matching the name you connect to (with SPIRE, register
//! the server entry with `-dns localhost`, for example).
//!
//! ## Rotation and Health
//!
//! Both providers subscribe to the Workload API and atomically swap in a new
//! config whenever SPIRE rotates the SVID or a trust bundle changes. Existing
//! connections keep the config they were established with.
//!
//! If the Workload API stream fails, the provider keeps serving the last good
//! config while it reconnects with exponential backoff. `stream_healthy()`
//! reports `false` until the stream is re-established, which is useful for
//! readiness checks.
//!
//! ## Trust Domains and Federation
//!
//! The list passed to `builder` selects which trust bundles are used as roots.
//! To accept peers from a federated trust domain (whose bundle SPIRE delivers
//! when the registration entry federates with it), include it alongside your
//! own:
//!
//! ```
//! # use rustls_spiffe::SpiffeServerConfigStream;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let builder = SpiffeServerConfigStream::builder(vec![
//!     "example.org".try_into()?,
//!     "partner.example.com".try_into()?,
//! ]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! All features are enabled by default via the `full` feature.
//!
//! | Feature          | Description                                                                 |
//! |------------------|-----------------------------------------------------------------------------|
//! | `config-stream`  | [`SpiffeClientConfigStream`], [`SpiffeServerConfigStream`], and the providers |
//! | `svid-extractor` | [`extract_leaf_cert`] and [`extract_spiffe_id`] for `tokio-rustls` servers  |
//! | `tracing`        | Logs workload identities, bundle loads, and stream reconnects via `tracing` |
//!
//! ## Crypto Provider
//!
//! This crate enables `rustls`'s `aws-lc-rs` backend. If something else in your
//! dependency tree enables another backend (e.g. `ring`), install a process
//! default before starting a provider:
//!
//! ```
//! // Errs only if a default is already installed, which is safe to ignore.
//! let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
//! ```
//!
//! [`rustls`]: https://docs.rs/rustls
//! [spiffe]: https://spiffe.io/docs/latest/spiffe-about/overview/
//! [`rustls-config-stream`]: https://docs.rs/rustls-config-stream
//! [`SpiffeClientConfigStream`]: https://docs.rs/rustls-spiffe/latest/rustls_spiffe/struct.SpiffeClientConfigStream.html
//! [`SpiffeServerConfigStream`]: https://docs.rs/rustls-spiffe/latest/rustls_spiffe/struct.SpiffeServerConfigStream.html
//! [`ClientConfigProvider`]: https://docs.rs/rustls-config-stream/latest/rustls_config_stream/struct.ClientConfigProvider.html
//! [`ServerConfigProvider`]: https://docs.rs/rustls-config-stream/latest/rustls_config_stream/struct.ServerConfigProvider.html
//! [`extract_leaf_cert`]: https://docs.rs/rustls-spiffe/latest/rustls_spiffe/fn.extract_leaf_cert.html
//! [`extract_spiffe_id`]: https://docs.rs/rustls-spiffe/latest/rustls_spiffe/fn.extract_spiffe_id.html

#![cfg_attr(docsrs, feature(doc_cfg))]
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
#[cfg(feature = "svid-extractor")]
mod svid_extractor;

#[cfg(feature = "config-stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "config-stream")))]
pub use client_stream::{ClientConfigProvider, SpiffeClientConfigStream};
#[cfg(feature = "config-stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "config-stream")))]
pub use server_stream::{ServerConfigProvider, SpiffeServerConfigStream};

mod trust_domain_store;
pub(crate) use trust_domain_store::TrustDomainStore;

#[cfg(feature = "svid-extractor")]
#[cfg_attr(docsrs, doc(cfg(feature = "svid-extractor")))]
pub use svid_extractor::{extract_leaf_cert, extract_spiffe_id};
