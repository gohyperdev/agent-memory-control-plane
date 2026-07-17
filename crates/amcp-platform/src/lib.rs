use anyhow::{Context, Result, bail};
use std::{env, path::PathBuf, process::Command};

pub const KEYCHAIN_SERVICE: &str = "com.gohyperdev.amcp.agent";

pub fn default_agent_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/AMCP/agent.sock"))
            .unwrap_or_else(|| PathBuf::from(".amcp/agent.sock"));
    }
    #[cfg(target_os = "windows")]
    {
        return env::var_os("LOCALAPPDATA")
            .map(|home| PathBuf::from(home).join("AMCP/agent.sock"))
            .unwrap_or_else(|| PathBuf::from("AMCP/agent.sock"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return env::var_os("XDG_RUNTIME_DIR")
            .map(|directory| PathBuf::from(directory).join("amcp-agent.sock"))
            .or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local/state/AMCP/agent.sock"))
            })
            .unwrap_or_else(|| PathBuf::from(".amcp/agent.sock"));
    }
    #[allow(unreachable_code)]
    PathBuf::from(".amcp/agent.sock")
}

pub trait SecretStore {
    fn get(&self) -> Result<Option<String>>;
    fn set(&self, value: &str) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct MacOsKeychain {
    pub service: String,
    pub account: String,
}

impl MacOsKeychain {
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_owned(),
            account: account.into(),
        }
    }

    pub fn with_service(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl SecretStore for MacOsKeychain {
    fn get(&self) -> Result<Option<String>> {
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-a",
                &self.account,
                "-s",
                &self.service,
                "-w",
            ])
            .output()
            .context("read AMCP credential from macOS Keychain")?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    }

    fn set(&self, value: &str) -> Result<()> {
        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-a",
                &self.account,
                "-s",
                &self.service,
                "-w",
                value,
                "-U",
            ])
            .output()
            .context("store AMCP credential in macOS Keychain")?;
        if !output.status.success() {
            bail!("macOS Keychain rejected AMCP credential")
        }
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        let output = Command::new("security")
            .args([
                "delete-generic-password",
                "-a",
                &self.account,
                "-s",
                &self.service,
            ])
            .output()
            .context("delete AMCP credential from macOS Keychain")?;
        if !output.status.success() {
            bail!("macOS Keychain rejected AMCP credential deletion")
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl SecretStore for MacOsKeychain {
    fn get(&self) -> Result<Option<String>> {
        bail!("AMCP macOS Keychain is unavailable on this platform")
    }

    fn set(&self, _value: &str) -> Result<()> {
        bail!("AMCP macOS Keychain is unavailable on this platform")
    }

    fn delete(&self) -> Result<()> {
        bail!("AMCP macOS Keychain is unavailable on this platform")
    }
}

pub fn keychain_account_for_host(host_id: &str) -> String {
    format!("agent:{host_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_accounts_are_host_scoped() {
        assert_eq!(keychain_account_for_host("host-a"), "agent:host-a");
        assert_ne!(
            keychain_account_for_host("host-a"),
            keychain_account_for_host("host-b")
        );
    }

    #[test]
    fn default_agent_socket_is_user_scoped() {
        let path = default_agent_socket_path();
        assert!(path.is_absolute() || path.starts_with(".amcp"));
        assert!(!path.to_string_lossy().is_empty());
    }
}
