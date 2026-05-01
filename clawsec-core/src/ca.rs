use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use time::OffsetDateTime;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tracing::info;

/// Manages the CA certificate and per-host certificate generation.
pub struct CertAuthority {
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    ca_cert_pem: String, // public access via ca_cert_pem()
    ctx_cache: Mutex<HashMap<String, rustls::ServerConfig>>,
}

impl CertAuthority {
    /// Generate or load the CA key and certificate.
    pub fn initialize(log_dir: &Path, enable_mitm: bool) -> anyhow::Result<Option<Self>> {
        if !enable_mitm {
            return Ok(None);
        }

        let ca_key_path = log_dir.join("ca.key");
        let ca_crt_path = log_dir.join("ca.crt");

        // Try loading existing CA key + regenerating cert
        if ca_key_path.exists() {
            match Self::load_or_generate(&ca_key_path, &ca_crt_path) {
                Ok(ca) => {
                    info!("MITM CA loaded from {}", ca_crt_path.display());
                    return Ok(Some(ca));
                }
                Err(e) => {
                    tracing::warn!("Failed to load CA ({}), generating fresh.", e);
                }
            }
        }

        // Generate fresh CA
        let ca = Self::generate()?;

        // Persist
        std::fs::create_dir_all(log_dir)?;
        let key_pem = ca.ca_key.serialize_pem();
        std::fs::write(&ca_key_path, key_pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ca_key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::write(&ca_crt_path, ca.ca_cert.pem().as_bytes())?;

        info!("MITM CA generated → {}", ca_crt_path.display());
        info!(
            "Install CA to inspect HTTPS:  sudo security add-trusted-cert -d -r trustRoot \
             -k /Library/Keychains/System.keychain {}",
            ca_crt_path.display()
        );

        Ok(Some(ca))
    }

    /// Load the CA key from PEM and regenerate the CA certificate with it.
    /// This produces a new CA cert (new serial number) but with the same key,
    /// so previously-signed host certs remain verifiable.
    fn load_or_generate(key_path: &Path, cert_path: &Path) -> anyhow::Result<Self> {
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("read CA key: {}", key_path.display()))?;
        let ca_key = KeyPair::from_pem(&key_pem).context("parse CA key PEM")?;

        // Generate a fresh CA cert with the loaded key
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).context("create CA cert params")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "ClawSec Monitor CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "ClawSec");
        ca_params.not_before = OffsetDateTime::now_utc();
        ca_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("self-sign CA certificate")?;
        let ca_cert_pem = ca_cert.pem().to_string();

        // Update cert file
        std::fs::write(cert_path, ca_cert.pem().as_bytes())?;

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_pem,
            ctx_cache: Mutex::new(HashMap::new()),
        })
    }

    fn generate() -> anyhow::Result<Self> {
        let ca_key = KeyPair::generate().context("generate CA key pair")?;

        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).context("create CA cert params")?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "ClawSec Monitor CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "ClawSec");
        ca_params.not_before = OffsetDateTime::now_utc();
        ca_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("self-sign CA certificate")?;
        let ca_cert_pem = ca_cert.pem().to_string();

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_pem,
            ctx_cache: Mutex::new(HashMap::new()),
        })
    }

    #[allow(dead_code)]
    /// Return the CA certificate PEM string (for display/trust instructions).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get or create a TLS server config for the given hostname.
    ///
    /// Generates a per-host certificate signed by our CA and caches
    /// the resulting `ServerConfig` for reuse.
    pub fn server_config_for_host(&self, hostname: &str) -> anyhow::Result<rustls::ServerConfig> {
        let mut cache = self.ctx_cache.lock().expect("cert cache lock poisoned");

        if let Some(cfg) = cache.get(hostname) {
            return Ok(cfg.clone());
        }

        // Generate a per-host certificate
        let host_key = KeyPair::generate().context("generate host key pair")?;

        let mut host_params = CertificateParams::new(vec![hostname.to_string()])
            .context("create host cert params")?;
        host_params.is_ca = IsCa::ExplicitNoCa;
        host_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        host_params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        host_params.not_before = OffsetDateTime::now_utc();
        host_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);

        let host_cert = host_params
            .signed_by(&host_key, &self.ca_cert, &self.ca_key)
            .context("sign host certificate")?;

        let cert_der = host_cert.der().to_vec();
        let key_der = host_key.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let key_pair = PrivateKeyDer::try_from(key_der)
            .map_err(|_| anyhow::anyhow!("invalid private key DER"))?;

        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_pair)
            .context("build TLS server config")?;

        cache.insert(hostname.to_string(), cfg.clone());
        Ok(cfg)
    }
}

unsafe impl Send for CertAuthority {}
unsafe impl Sync for CertAuthority {}
