// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rustls_config_stream::{ClientConfigStreamBuilder, ClientConfigStreamError};
use spiffe::{TrustDomain, WorkloadApiClient, X509Context, error::GrpcClientError};
use tokio_stream::Stream;

pub use rustls_config_stream::ClientConfigProvider;

#[cfg(feature = "tracing")]
use tracing::debug;

use crate::TrustDomainStore;

/// Builder for a [`SpiffeClientConfigStream`] that provides [`rustls::ClientConfig`]
/// objects built w/ trust bundles and workload X509-SVID from SPIFFE.
///
/// The builder controls which SPIFFE trust bundles are included in the
/// internal [`rustls::RootCertStore`] used to build the [`ClientConfig`]
pub struct SpiffeClientConfigStreamBuilder {
    trust_domains: Vec<TrustDomain>,
    client: Option<WorkloadApiClient>,
}

impl SpiffeClientConfigStreamBuilder {
    /// Create a builder that can create [`SpiffeClientConfigStream`] objects
    /// with the provided SPIFFE trust domains.
    const fn new(trust_domains: Vec<TrustDomain>) -> Self {
        Self {
            trust_domains,
            client: None,
        }
    }
}

impl ClientConfigStreamBuilder for SpiffeClientConfigStreamBuilder {
    type ConfigStream = SpiffeClientConfigStream;

    async fn build(&mut self) -> Result<Self::ConfigStream, ClientConfigStreamError> {
        let client = if let Some(client) = &mut self.client {
            client
        } else {
            &mut WorkloadApiClient::default()
                .await
                .map_err(|e| ClientConfigStreamError::StreamBuilderError(e.into()))?
        };
        Ok(SpiffeClientConfigStream {
            trust_domains: self.trust_domains.clone(),
            inner: Pin::from(Box::from(
                client
                    .stream_x509_contexts()
                    .await
                    .map_err(|e| ClientConfigStreamError::StreamError(e.into()))?,
            )),
        })
    }
}

/// A stream that yields updated [`rustls::ClientConfig`] values derived from the
/// SPIFFE Workload API X509-SVID and Trust Bundles.
///
/// Each yielded config:
/// * Uses the workload's default SVID (certificate chain + private key).
/// * Requires (and verifies) server certificates whose trust anchors come from
///   the configured SPIFFE trust domains.
///
/// # Behavior
///
/// * If the Workload API stream returns an error, this stream yields
///   a [`ClientConfigStreamError::StreamError`] wrapping the original
///   [`GrpcClientError`].
/// * If an update lacks roots/SVID or the verifier cannot be built, the error
///   is returned on the stream as a [`ClientConfigStreamError`]
pub struct SpiffeClientConfigStream {
    inner:
        Pin<Box<dyn Stream<Item = Result<X509Context, GrpcClientError>> + Send + Sync + 'static>>,
    trust_domains: Vec<TrustDomain>,
}

impl TrustDomainStore for SpiffeClientConfigStream {
    fn get_trust_domains(&self) -> &Vec<TrustDomain> {
        &self.trust_domains
    }
}

impl SpiffeClientConfigStream {
    /// Create a builder that can create [`SpiffeClientConfigStream`] objects
    /// with the provided SPIFFE trust domains.
    #[must_use]
    pub const fn builder(trust_domains: Vec<TrustDomain>) -> SpiffeClientConfigStreamBuilder {
        SpiffeClientConfigStreamBuilder::new(trust_domains)
    }

    fn build_client_config(
        &self,
        x509_context: &X509Context,
    ) -> Result<Arc<ClientConfig>, ClientConfigStreamError> {
        let roots = self.build_root_store(x509_context.bundle_set());
        if roots.is_empty() {
            return Err(ClientConfigStreamError::MissingRoots);
        }
        let svid = x509_context
            .default_svid()
            .ok_or(ClientConfigStreamError::MissingCertifiedKey)?;

        #[cfg(feature = "tracing")]
        debug!(workload_identity = %svid.spiffe_id());

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                svid.cert_chain()
                    .iter()
                    .map(|c| CertificateDer::from(c.content().to_owned()))
                    .collect(),
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                    svid.private_key().content().to_owned(),
                )),
            )
            .map_err(ClientConfigStreamError::RustlsError)?;
        Ok(Arc::from(config))
    }
}

impl Stream for SpiffeClientConfigStream {
    type Item = Result<Arc<ClientConfig>, ClientConfigStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => {
                Poll::Ready(Some(Err(ClientConfigStreamError::StreamError(err.into()))))
            }
            Poll::Ready(Some(Ok(x509_context))) => match self.build_client_config(&x509_context) {
                Ok(config) => Poll::Ready(Some(Ok(config))),
                Err(err) => Poll::Ready(Some(Err(err))),
            },
        }
    }
}
