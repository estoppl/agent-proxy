use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

/// Manages Ed25519 keypair for signing audit events.
pub struct KeyManager {
    signing_key: SigningKey,
    pub key_id: String,
}

impl KeyManager {
    /// Load an existing keypair from disk, or generate a new one.
    pub fn load_or_generate(key_dir: &Path) -> Result<Self> {
        let private_path = key_dir.join("estoppl-signing.key");
        let public_path = key_dir.join("estoppl-signing.pub");

        let signing_key = if private_path.exists() {
            let bytes = std::fs::read(&private_path)
                .context("Failed to read signing key")?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key file: expected 32 bytes"))?;
            SigningKey::from_bytes(&key_bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::create_dir_all(key_dir)
                .context("Failed to create key directory")?;
            std::fs::write(&private_path, key.to_bytes())
                .context("Failed to write signing key")?;
            std::fs::write(&public_path, key.verifying_key().to_bytes())
                .context("Failed to write public key")?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))?;
            }

            tracing::info!("Generated new Ed25519 keypair at {}", key_dir.display());
            key
        };

        let key_id = hex::encode(&signing_key.verifying_key().to_bytes()[..8]);

        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Sign arbitrary bytes, returning the base64-encoded signature.
    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes())
    }

    /// Return the public verifying key (used for signature verification).
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
