use std::io;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::AppConfig;

/// Derive an obfuscated storage path from an attachment ID.
/// Uses HMAC-SHA256(server_key, attachment_id) so the filesystem reveals
/// nothing about user or attachment identity.
/// Returns a path like "ab/cdef0123456789..." for directory sharding.
pub fn obfuscated_key(server_key: &[u8; 32], attachment_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_key)
        .expect("HMAC key length is always valid");
    mac.update(attachment_id.as_bytes());
    let result = mac.finalize().into_bytes();
    let hex_str = hex::encode(result);
    // Shard: first 2 chars as subdirectory
    format!("{}/{}", &hex_str[..2], &hex_str[2..])
}

// ─── Encryption helpers ──────────────────────────────────

fn encrypt_blob(data: &[u8], server_key: &[u8; 32]) -> io::Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(server_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| io::Error::other(format!("Encryption failed: {}", e)))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_blob(data: &[u8], server_key: &[u8; 32]) -> io::Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stored blob too short (missing nonce)",
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(server_key);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| io::Error::other(format!("Decryption failed: {}", e)))
}

// ─── Storage Backend ──────────────────────────────────────

/// Abstraction over local filesystem and S3 storage.
/// Both backends apply the same AES-256-GCM server-side encryption.
#[derive(Clone)]
pub enum Storage {
    Local {
        dir: PathBuf,
        encryption_key: [u8; 32],
    },
    S3 {
        client: aws_sdk_s3::Client,
        bucket: String,
        encryption_key: [u8; 32],
    },
}

impl Storage {
    /// Build a Storage backend from config.
    pub async fn from_config(config: &AppConfig) -> Self {
        let key_bytes = hex::decode(&config.storage_encryption_key)
            .expect("STORAGE_ENCRYPTION_KEY must be valid hex");
        let encryption_key: [u8; 32] = key_bytes
            .try_into()
            .expect("STORAGE_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)");

        if config.storage_backend == "s3" {
            let creds = aws_credential_types::Credentials::new(
                &config.s3_access_key,
                &config.s3_secret_key,
                None,
                None,
                "haven-env",
            );

            let mut s3_config_builder = aws_sdk_s3::config::Builder::new()
                .region(aws_sdk_s3::config::Region::new(config.s3_region.clone()))
                .credentials_provider(creds)
                .force_path_style(true); // Required for MinIO / custom endpoints

            if !config.s3_endpoint.is_empty() {
                s3_config_builder = s3_config_builder
                    .endpoint_url(&config.s3_endpoint);
            }

            let client = aws_sdk_s3::Client::from_conf(s3_config_builder.build());

            tracing::info!("S3 storage initialized (bucket: {})", config.s3_bucket);
            Storage::S3 {
                client,
                bucket: config.s3_bucket.clone(),
                encryption_key,
            }
        } else {
            std::fs::create_dir_all(&config.storage_dir)
                .expect("Failed to create storage directory");
            tracing::info!("Local storage initialized at {}", config.storage_dir);
            Storage::Local {
                dir: PathBuf::from(&config.storage_dir),
                encryption_key,
            }
        }
    }

    /// Returns the raw encryption key (needed for obfuscated_key derivation).
    pub fn encryption_key(&self) -> &[u8; 32] {
        match self {
            Storage::Local { encryption_key, .. } => encryption_key,
            Storage::S3 { encryption_key, .. } => encryption_key,
        }
    }

    /// Encrypt data and store it.
    pub async fn store_blob(&self, storage_key: &str, data: &[u8]) -> io::Result<()> {
        let encrypted = encrypt_blob(data, self.encryption_key())?;

        match self {
            Storage::Local { dir, .. } => {
                let path = dir.join(storage_key);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&path, &encrypted).await
            }
            Storage::S3 { client, bucket, .. } => {
                client
                    .put_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(encrypted))
                    .send()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 put failed: {}", e))
                    })?;
                Ok(())
            }
        }
    }

    /// Store raw bytes without server-side encryption. Used when CDN is enabled
    /// (client-side E2EE is sufficient; no need for double encryption).
    pub async fn store_blob_raw(&self, storage_key: &str, data: &[u8]) -> io::Result<()> {
        match self {
            Storage::Local { dir, .. } => {
                let path = dir.join(storage_key);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&path, data).await
            }
            Storage::S3 { client, bucket, .. } => {
                client
                    .put_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data.to_vec()))
                    .send()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 put failed: {}", e))
                    })?;
                Ok(())
            }
        }
    }

    /// Load raw bytes without decryption. Used when CDN is enabled.
    pub async fn load_blob_raw(&self, storage_key: &str) -> io::Result<Vec<u8>> {
        match self {
            Storage::Local { dir, .. } => {
                let path = dir.join(storage_key);
                tokio::fs::read(&path).await
            }
            Storage::S3 { client, bucket, .. } => {
                let output = client
                    .get_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .send()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 get failed: {}", e))
                    })?;

                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 read body failed: {}", e))
                    })?
                    .into_bytes()
                    .to_vec();
                Ok(bytes)
            }
        }
    }

    /// Generate a presigned GET URL for direct client download.
    /// Returns None for local storage (no presigning possible).
    /// If `cdn_base_url` is provided, the S3 host is replaced with the CDN domain.
    pub async fn presign_url(
        &self,
        storage_key: &str,
        expiry_secs: u64,
        cdn_base_url: &str,
    ) -> Option<String> {
        match self {
            Storage::Local { .. } => None,
            Storage::S3 { client, bucket, .. } => {
                let presign_config = aws_sdk_s3::presigning::PresigningConfig::builder()
                    .expires_in(std::time::Duration::from_secs(expiry_secs))
                    .build()
                    .ok()?;

                let presigned = client
                    .get_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .presigned(presign_config)
                    .await
                    .ok()?;

                let url = presigned.uri().to_string();

                if cdn_base_url.is_empty() {
                    Some(url)
                } else {
                    // Replace the S3 host with CDN domain
                    // URL format: https://s3-host/bucket/key?params
                    // Skip past "https://" (8 chars) then find the next '/'
                    let path_start = url[8..].find('/').map(|i| i + 8);
                    if let Some(idx) = path_start {
                        Some(format!("{}{}", cdn_base_url.trim_end_matches('/'), &url[idx..]))
                    } else {
                        Some(url)
                    }
                }
            }
        }
    }

    /// Delete a stored blob (file or S3 object).
    pub async fn delete_blob(&self, storage_key: &str) -> io::Result<()> {
        match self {
            Storage::Local { dir, .. } => {
                let path = dir.join(storage_key);
                match tokio::fs::remove_file(&path).await {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Storage::S3 { client, bucket, .. } => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .send()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 delete failed: {}", e))
                    })?;
                Ok(())
            }
        }
    }

    /// Load and decrypt data.
    pub async fn load_blob(&self, storage_key: &str) -> io::Result<Vec<u8>> {
        let encrypted = match self {
            Storage::Local { dir, .. } => {
                let path = dir.join(storage_key);
                tokio::fs::read(&path).await?
            }
            Storage::S3 { client, bucket, .. } => {
                let output = client
                    .get_object()
                    .bucket(bucket)
                    .key(storage_key)
                    .send()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 get failed: {}", e))
                    })?;

                output
                    .body
                    .collect()
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("S3 read body failed: {}", e))
                    })?
                    .into_bytes()
                    .to_vec()
            }
        };

        decrypt_blob(&encrypted, self.encryption_key())
    }
}

// ─── Legacy free functions (kept for backward compatibility) ──

/// Encrypt data with AES-256-GCM and write to disk.
/// File format: [12-byte nonce || ciphertext+tag]
pub async fn store_blob(
    storage_dir: &Path,
    storage_key: &str,
    data: &[u8],
    server_key: &[u8; 32],
) -> io::Result<()> {
    let encrypted = encrypt_blob(data, server_key)?;
    let path = storage_dir.join(storage_key);

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(&path, &encrypted).await
}

/// Read from disk and decrypt with AES-256-GCM.
pub async fn load_blob(
    storage_dir: &Path,
    storage_key: &str,
    server_key: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let path = storage_dir.join(storage_key);
    let data = tokio::fs::read(&path).await?;
    decrypt_blob(&data, server_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── obfuscated_key ──────────────────────────────────

    #[test]
    fn obfuscated_key_format() {
        let key = [0u8; 32];
        let result = obfuscated_key(&key, "test-attachment-id");
        // Should be "xx/yyyyyyyy..." format (2 char dir / rest of hex)
        let parts: Vec<&str> = result.splitn(2, '/').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 2);
        assert!(parts[1].len() > 10);
    }

    #[test]
    fn obfuscated_key_deterministic() {
        let key = [42u8; 32];
        let a = obfuscated_key(&key, "same-id");
        let b = obfuscated_key(&key, "same-id");
        assert_eq!(a, b);
    }

    #[test]
    fn obfuscated_key_different_ids() {
        let key = [42u8; 32];
        let a = obfuscated_key(&key, "id-a");
        let b = obfuscated_key(&key, "id-b");
        assert_ne!(a, b);
    }

    #[test]
    fn obfuscated_key_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let a = obfuscated_key(&key1, "same-id");
        let b = obfuscated_key(&key2, "same-id");
        assert_ne!(a, b);
    }

    // ─── encrypt_blob / decrypt_blob ─────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"Hello, world! This is test data.";
        let encrypted = encrypt_blob(plaintext, &key).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = decrypt_blob(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertext() {
        let key = [0u8; 32];
        let plaintext = b"same data";
        let e1 = encrypt_blob(plaintext, &key).unwrap();
        let e2 = encrypt_blob(plaintext, &key).unwrap();
        // Random nonce means ciphertext differs each time
        assert_ne!(e1, e2);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt_blob(b"secret", &key1).unwrap();
        assert!(decrypt_blob(&encrypted, &key2).is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = [0u8; 32];
        // Less than 12 bytes (nonce size)
        assert!(decrypt_blob(&[0u8; 5], &key).is_err());
    }

    #[test]
    fn decrypt_corrupted_data_fails() {
        let key = [0u8; 32];
        let mut encrypted = encrypt_blob(b"data", &key).unwrap();
        // Corrupt a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_blob(&encrypted, &key).is_err());
    }

    #[test]
    fn encrypt_empty_data() {
        let key = [0u8; 32];
        let encrypted = encrypt_blob(b"", &key).unwrap();
        let decrypted = decrypt_blob(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    // ─── Storage::encryption_key ─────────────────────────

    #[test]
    fn local_storage_returns_key() {
        let key = [42u8; 32];
        let storage = Storage::Local {
            dir: PathBuf::from("/tmp"),
            encryption_key: key,
        };
        assert_eq!(storage.encryption_key(), &key);
    }

    // ─── store_blob / load_blob (legacy free functions) ──

    #[tokio::test]
    async fn store_and_load_blob_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0u8; 32];
        let data = b"test file contents for roundtrip";

        store_blob(dir.path(), "test/file.enc", data, &key).await.unwrap();
        let loaded = load_blob(dir.path(), "test/file.enc", &key).await.unwrap();
        assert_eq!(loaded, data);
    }

    #[tokio::test]
    async fn load_blob_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0u8; 32];
        assert!(load_blob(dir.path(), "missing.enc", &key).await.is_err());
    }

    // ─── Storage::store_blob / load_blob (Local backend) ─

    #[tokio::test]
    async fn storage_local_store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0u8; 32];
        let storage = Storage::Local {
            dir: dir.path().to_path_buf(),
            encryption_key: key,
        };

        let data = b"encrypted at rest test data";
        storage.store_blob("ab/test.enc", data).await.unwrap();
        let loaded = storage.load_blob("ab/test.enc").await.unwrap();
        assert_eq!(loaded, data);
    }

    #[tokio::test]
    async fn storage_local_raw_store_load() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0u8; 32];
        let storage = Storage::Local {
            dir: dir.path().to_path_buf(),
            encryption_key: key,
        };

        let data = b"raw unencrypted data";
        storage.store_blob_raw("raw/test.bin", data).await.unwrap();
        let loaded = storage.load_blob_raw("raw/test.bin").await.unwrap();
        assert_eq!(loaded, data.to_vec());
    }

    #[tokio::test]
    async fn storage_local_presign_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0u8; 32];
        let storage = Storage::Local {
            dir: dir.path().to_path_buf(),
            encryption_key: key,
        };
        let result = storage.presign_url("key", 3600, "").await;
        assert!(result.is_none());
    }
}
