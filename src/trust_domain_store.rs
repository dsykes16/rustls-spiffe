// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use rustls::{RootCertStore, pki_types::CertificateDer};
use spiffe::{TrustDomain, X509Bundle, X509BundleSet};
use std::sync::Arc;
#[cfg(feature = "tracing")]
use tracing::debug;

pub trait TrustDomainStore {
    fn get_trust_domains(&self) -> &Vec<TrustDomain>;
    fn build_root_store(&self, bundles: &X509BundleSet) -> Arc<RootCertStore> {
        let mut root_store = RootCertStore::empty();
        let root_certs = self
            .get_trust_domains()
            .iter()
            .filter_map(|domain| bundles.get_bundle(domain))
            .flat_map(X509Bundle::authorities)
            .map(|authority| CertificateDer::from_slice(authority.content()));

        let (added, ignored) = root_store.add_parsable_certificates(root_certs);

        #[cfg(feature = "tracing")]
        debug!(added, ignored);

        Arc::new(root_store)
    }
}
