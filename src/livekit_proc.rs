//! Managed LiveKit subprocess for bundled voice support.
//!
//! When no external LiveKit server is configured, Haven can auto-discover
//! and start a local `livekit-server` binary as a child process.

use rand::Rng;
use std::path::PathBuf;
use tokio::process::Child;

/// A managed LiveKit server process.
///
/// When dropped, the child process is automatically killed (kill_on_drop).
pub struct LiveKitProcess {
    _child: Child,
    config_path: PathBuf,
}

impl Drop for LiveKitProcess {
    fn drop(&mut self) {
        // Clean up the config file we wrote.
        // Child process killed automatically by tokio (kill_on_drop: true).
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Result of successfully starting a bundled LiveKit instance.
pub struct BundledLiveKit {
    pub process: LiveKitProcess,
    pub url: String,
    pub api_key: String,
    pub api_secret: String,
}

/// Search for the `livekit-server` binary in well-known locations.
pub fn find_livekit_binary() -> Option<PathBuf> {
    // 1. Same directory as the Haven executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidate = exe_dir.join("livekit-server");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 2. ./bin/ directory
    let bin_candidate = PathBuf::from("./bin/livekit-server");
    if bin_candidate.is_file() {
        return Some(bin_candidate);
    }

    // 3. System PATH
    which::which("livekit-server").ok()
}

fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let hex: String = (0..8).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();
    format!("haven_{}", hex)
}

fn generate_api_secret() -> String {
    let mut rng = rand::thread_rng();
    (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

fn build_config_yaml(port: u16, api_key: &str, api_secret: &str) -> String {
    format!(
        r#"port: {port}
rtc:
  port_range_start: {rtc_start}
  port_range_end: {rtc_end}
  use_external_ip: false
  tcp_port: {tcp_port}
keys:
  {api_key}: {api_secret}
logging:
  level: info
room:
  auto_create: true
  empty_timeout: 300
  max_participants: 50
"#,
        port = port,
        rtc_start = port + 2,
        rtc_end = port + 12,
        tcp_port = port + 1,
        api_key = api_key,
        api_secret = api_secret,
    )
}

/// Discover a `livekit-server` binary and start it as a managed subprocess.
///
/// Returns `None` if the binary is not found or fails to start.
/// The returned `BundledLiveKit` includes the process handle (which must be
/// kept alive for the duration of the program) and the generated credentials.
pub async fn start_bundled_livekit(port: u16) -> Option<BundledLiveKit> {
    let binary = find_livekit_binary()?;
    tracing::info!("Found LiveKit binary at: {:?}", binary);

    let api_key = generate_api_key();
    let api_secret = generate_api_secret();

    let config_path = PathBuf::from("./data/livekit.yaml");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let yaml = build_config_yaml(port, &api_key, &api_secret);
    if let Err(e) = std::fs::write(&config_path, &yaml) {
        tracing::error!("Failed to write LiveKit config to {:?}: {}", config_path, e);
        return None;
    }

    let log_path = PathBuf::from("./data/livekit.log");
    let log_file = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to create LiveKit log file {:?}: {}", log_path, e);
            let _ = std::fs::remove_file(&config_path);
            return None;
        }
    };
    let log_stderr = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to clone log file handle: {}", e);
            let _ = std::fs::remove_file(&config_path);
            return None;
        }
    };

    let child = match tokio::process::Command::new(&binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_stderr))
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to spawn LiveKit process: {}", e);
            let _ = std::fs::remove_file(&config_path);
            return None;
        }
    };

    tracing::info!("Waiting for managed LiveKit to start on port {}...", port);
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let url = format!("ws://127.0.0.1:{}", port);
    tracing::info!("Managed LiveKit started: {}", url);

    Some(BundledLiveKit {
        process: LiveKitProcess {
            _child: child,
            config_path,
        },
        url,
        api_key,
        api_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("haven_"));
        assert_eq!(key.len(), 6 + 16); // "haven_" + 16 hex chars
    }

    #[test]
    fn api_secret_length() {
        let secret = generate_api_secret();
        assert_eq!(secret.len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn config_yaml_contains_expected_values() {
        let yaml = build_config_yaml(7880, "haven_abcd1234abcd1234", "secret123");
        assert!(yaml.contains("port: 7880"));
        assert!(yaml.contains("tcp_port: 7881"));
        assert!(yaml.contains("port_range_start: 7882"));
        assert!(yaml.contains("port_range_end: 7892"));
        assert!(yaml.contains("haven_abcd1234abcd1234:"));
        assert!(yaml.contains("auto_create: true"));
    }
}
