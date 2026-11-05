//! TLS client configurations for Kafka connections (rustls with the ring provider).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, SignatureScheme, WantsVerifier};

/// TLS for broker connections: the system roots when `verify`, else no server certificate check
/// (as in FlowLink with `verify_cert` off). No client certificate.
pub fn server_config(verify: bool) -> Arc<ClientConfig> {
    let (builder, provider) = builder();
    let config = if verify {
        builder.with_root_certificates(system_roots()).with_no_client_auth()
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    };
    Arc::new(config)
}

/// System roots plus a client certificate (PEM chain and key). Both empty: system roots, no client
/// certificate.
pub fn client_auth_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ClientConfig>, String> {
    let builder = builder().0.with_root_certificates(system_roots());
    if cert_pem.is_empty() && key_pem.is_empty() {
        return Ok(Arc::new(builder.with_no_client_auth()));
    }
    let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("client certificate: {e}"))?;
    if chain.is_empty() {
        return Err("client certificate: no certificate in PEM".to_string());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| format!("client key: {e}"))?;
    builder.with_client_auth_cert(chain, key).map(Arc::new).map_err(|e| format!("client certificate: {e}"))
}

fn builder() -> (ConfigBuilder<ClientConfig, WantsVerifier>, Arc<CryptoProvider>) {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions");
    (builder, provider)
}

/// The system trust store, shared by every config here. Unreadable or invalid entries are skipped.
fn system_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots
}

/// Accepts any server certificate; signatures are still checked so the handshake is well-formed.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_verify_accepts_any_certificate() {
        let (_, provider) = builder();
        let v = NoVerify(provider);
        let name = ServerName::try_from("kafka").unwrap();
        assert!(v.verify_server_cert(&CertificateDer::from(vec![0u8; 4]), &[], &name, &[], UnixTime::now()).is_ok());
        assert!(!v.supported_verify_schemes().is_empty());
    }

    #[test]
    fn server_config_has_no_client_certificate() {
        assert!(!server_config(true).client_auth_cert_resolver.has_certs());
        assert!(!server_config(false).client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn client_auth_without_pem_is_plain_system_roots() {
        let c = client_auth_config("", "").unwrap();
        assert!(!c.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn client_auth_rejects_incomplete_or_bad_pem() {
        assert!(client_auth_config("", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
            .unwrap_err()
            .contains("no certificate"));
        let cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(client_auth_config(cert, "").unwrap_err().starts_with("client key:"));
        assert!(client_auth_config(cert, "garbage").unwrap_err().starts_with("client key:"));
    }
}
