use rustls_spiffe::{
    ClientConfigProvider, ServerConfigProvider, SpiffeClientConfigStream, SpiffeServerConfigStream,
};

use rustls::pki_types::CertificateDer;
use spiffe::SpiffeId;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::GeneralName;

#[inline(always)]
pub(crate) fn extract_leaf_cert(stream: &TlsStream<TcpStream>) -> Option<&CertificateDer> {
    let (_, state) = stream.get_ref();
    let peer_certificates = state.peer_certificates();
    let chain = peer_certificates?;
    let leaf = chain.first()?;
    Some(leaf)
}

#[inline(always)]
pub(crate) fn extract_spiffe_id(leaf: Option<&CertificateDer>) -> Option<SpiffeId> {
    let leaf = leaf?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    let uri = san.value.general_names.iter().find_map(|gn| match gn {
        GeneralName::URI(uri) => Some(*uri),
        _ => None,
    })?;
    SpiffeId::try_from(uri).ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_handshake() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .unwrap();
    let (req, res) = tokio::join!(oneshot_server(), client());
    let res = res.unwrap();
    let req = req.unwrap();
    assert_eq!(req.data, "PING",);
    assert_eq!(
        req.svid,
        "spiffe://example.org/testservice".try_into().unwrap()
    );
    assert_eq!(res, "PONG",);
}

struct Request {
    data: String,
    svid: SpiffeId,
}

async fn oneshot_server() -> Result<Request, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    let config_stream_builder =
        SpiffeServerConfigStream::builder(vec!["example.org".try_into().unwrap()]);
    let config_provider = ServerConfigProvider::start(config_stream_builder)
        .await
        .unwrap();

    let (stream, _) = listener.accept().await.unwrap();

    let acceptor =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    tokio::pin!(acceptor);

    let config_provider = config_provider.clone();
    match acceptor.as_mut().await {
        Ok(start) => {
            let config = config_provider.get_config();
            let mut stream = start.into_stream(config).await.unwrap();
            let leaf = extract_leaf_cert(&stream);
            let svid = extract_spiffe_id(leaf).unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            stream.write_all("PONG".as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            Ok(Request {
                data: String::from_utf8_lossy(&buf).to_string(),
                svid,
            })
        }
        Err(err) => {
            if let Some(mut stream) = acceptor.take_io() {
                stream.write_all("FAIL".as_bytes()).await.unwrap();
            }
            Err(err.into())
        }
    }
}

async fn client() -> Result<String, Box<dyn std::error::Error>> {
    let stream = tokio::net::TcpStream::connect("127.0.0.1:3000")
        .await
        .unwrap();
    let config_provider = ClientConfigProvider::start(SpiffeClientConfigStream::builder(vec![
        "example.org".try_into().unwrap(),
    ]))
    .await
    .unwrap();
    let connector = tokio_rustls::TlsConnector::from(config_provider.get_config());
    let tstream = connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();
    let (mut rx, mut tx) = tokio::io::split(tstream);
    tx.write_all("PING".as_bytes()).await.unwrap();
    tx.shutdown().await.unwrap();
    let mut buf = Vec::new();
    rx.read_to_end(&mut buf).await.unwrap();
    let res = String::from_utf8_lossy(&buf).to_string();
    Ok(res)
}
