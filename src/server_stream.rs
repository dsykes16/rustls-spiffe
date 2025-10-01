// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use rustls_config_stream::{ServerConfigStreamBuilder, ServerConfigStreamError};
use spiffe::{TrustDomain, WorkloadApiClient, X509BundleSet, X509Context, error::GrpcClientError};
use tokio_stream::Stream;

pub use rustls_config_stream::ServerConfigProvider;

#[cfg(feature = "tracing")]
use tracing::debug;

/// Builder for a [`SpiffeServerConfigStream`] that provides [`rustls::ServerConfig`]
/// objects built w/ trust bundles and workload X509-SVID from SPIFFE.
///
/// The builder controls which SPIFFE trust domains are allowed to authenticate
/// clients.
pub struct SpiffeServerConfigStreamBuilder {
    trust_domains: Vec<TrustDomain>,
    client: Option<WorkloadApiClient>,
}

impl SpiffeServerConfigStreamBuilder {
    /// Create a builder that can create [`SpiffeServerConfigStream`] objects
    /// with the provided SPIFFE trust domains.
    fn new(trust_domains: Vec<TrustDomain>) -> Self {
        Self {
            trust_domains,
            client: None,
        }
    }
}
impl ServerConfigStreamBuilder for SpiffeServerConfigStreamBuilder {
    type ConfigStream = SpiffeServerConfigStream;

    async fn build(&mut self) -> Result<Self::ConfigStream, ServerConfigStreamError> {
        let client = if let Some(client) = &mut self.client {
            client
        } else {
            &mut WorkloadApiClient::default()
                .await
                .map_err(|e| ServerConfigStreamError::StreamBuilderError(e.into()))?
        };
        Ok(SpiffeServerConfigStream {
            trust_domains: self.trust_domains.to_owned(),
            inner: Pin::from(Box::from(
                client
                    .stream_x509_contexts()
                    .await
                    .map_err(|e| ServerConfigStreamError::StreamError(e.into()))?,
            )),
        })
    }
}

/// A stream that yields updated `rustls::ServerConfig` values derived from the
/// SPIFFE Workload API X509-SVID and Trust Bundles.
///
/// Each yielded config:
/// * Uses the workload's default SVID (certificate chain + private key).
/// * Requires (and verifies) client certificates whose trust anchors come from
///   the configured SPIFFE trust domains.
///
/// # Behavior
///
/// * If the Workload API stream returns an error, this stream yields
///   a [`ServerConfigStreamError::StreamError`] wrapping the original
///   [`GrpcClientError`].
/// * If an update lacks roots/SVID or the verifier cannot be built, the error
///   is returned on the stream as a [`ServerConfigStreamError`]
///
/// # Usage
///
/// ```rust
/// use rustls_spiffe::{SpiffeServerConfigStream, ServerConfigProvider};
/// use tracing::warn;
///
/// async fn run() {
///     let config_stream_builder =
///         SpiffeServerConfigStream::builder(vec!["example.org".try_into().unwrap()]);
///     let config_provider = ServerConfigProvider::start(config_stream_builder)
///         .await
///         .unwrap();
///     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
///         .await
///         .unwrap();
///     loop {
///         let (stream, _) = listener.accept().await.unwrap();
///
///         let acceptor =
///             tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
///         tokio::pin!(acceptor);
///
///         let config_provider = config_provider.clone();
///         match acceptor.as_mut().await {
///             Ok(start) => {
///                 tokio::spawn(async move {
///                     if !config_provider.stream_healthy() {
///                         warn!(
///                             "config provider does not have healthy stream; TLS config may be out of date"
///                         );
///                     }
///                     let config = config_provider.get_config();
///                     match start.into_stream(config).await {
///                         Ok(stream) => {
///                             // serve some app (e.g. hyper, tower, axum)
///                             todo!();
///                         }
///                         Err(err) => {
///                             // add error handling as-desired
///                             todo!()
///                         },
///                     }
///                 });
///             }
///             Err(err) => {
///                 // add error-handling as-desired
///                 todo!()
///             },
///         }
///     }
/// }
/// ```

pub struct SpiffeServerConfigStream {
    inner:
        Pin<Box<dyn Stream<Item = Result<X509Context, GrpcClientError>> + Send + Sync + 'static>>,
    trust_domains: Vec<TrustDomain>,
}

impl SpiffeServerConfigStream {
    /// Create a builder that can create [`SpiffeServerConfigStream`] objects
    /// with the provided SPIFFE trust domains.
    pub fn builder(trust_domains: Vec<TrustDomain>) -> SpiffeServerConfigStreamBuilder {
        SpiffeServerConfigStreamBuilder::new(trust_domains)
    }

    fn build_root_store(&self, bundles: &X509BundleSet) -> Arc<RootCertStore> {
        let mut root_store = RootCertStore::empty();
        let root_certs = self
            .trust_domains
            .iter()
            .filter_map(|domain| bundles.get_bundle(domain))
            .flat_map(|bundle| bundle.authorities())
            .map(|authority| CertificateDer::from_slice(authority.content()));

        let (added, ignored) = root_store.add_parsable_certificates(root_certs);

        #[cfg(feature = "tracing")]
        debug!(added, ignored);

        Arc::new(root_store)
    }

    fn build_server_config(
        &self,
        x509_context: X509Context,
    ) -> Result<Arc<ServerConfig>, ServerConfigStreamError> {
        let roots = self.build_root_store(x509_context.bundle_set());
        if roots.is_empty() {
            return Err(ServerConfigStreamError::MissingRoots);
        }
        let verifier = WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|e| ServerConfigStreamError::VerifierBuilderError(e))?;
        let svid = x509_context
            .default_svid()
            .ok_or(ServerConfigStreamError::MissingCertifiedKey)?;

        #[cfg(feature = "tracing")]
        debug!(workload_identity = %svid.spiffe_id());

        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                svid.cert_chain()
                    .iter()
                    .map(|c| CertificateDer::from(c.content().to_owned()))
                    .collect(),
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                    svid.private_key().content().to_owned(),
                )),
            )
            .map_err(|e| ServerConfigStreamError::RustlsError(e))?;
        Ok(Arc::from(config))
    }
}

impl Stream for SpiffeServerConfigStream {
    type Item = Result<Arc<ServerConfig>, ServerConfigStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => {
                Poll::Ready(Some(Err(ServerConfigStreamError::StreamError(err.into()))))
            }
            Poll::Ready(Some(Ok(x509_context))) => match self.build_server_config(x509_context) {
                Ok(config) => Poll::Ready(Some(Ok(config))),
                Err(err) => Poll::Ready(Some(Err(err))),
            },
        }
    }
}
