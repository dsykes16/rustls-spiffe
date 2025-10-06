use rustls::pki_types::CertificateDer;
use spiffe::SpiffeId;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::GeneralName;

/// Extract the leaf [`CertificateDer`] from a [`TlsStream`]
#[inline]
#[must_use]
pub fn extract_leaf_cert(stream: &TlsStream<TcpStream>) -> Option<&CertificateDer<'_>> {
    let (_, state) = stream.get_ref();
    let peer_certificates = state.peer_certificates()?;
    let leaf = peer_certificates.first()?;
    Some(leaf)
}

/// Extract a [`SpiffeId`] from a [`CertificateDer`] if the certificate is a valid X509-SVID
#[inline]
#[must_use]
pub fn extract_spiffe_id(leaf: Option<&CertificateDer<'_>>) -> Option<SpiffeId> {
    let leaf = leaf?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    let uri = san.value.general_names.iter().find_map(|gn| match gn {
        GeneralName::URI(uri) => Some(*uri),
        _ => None,
    })?;
    SpiffeId::try_from(uri).ok()
}
