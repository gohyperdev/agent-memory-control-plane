use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const KEYCHAIN_SERVICE: &str = "com.gohyperdev.amcp.agent";
pub const CREDENTIAL_STORE_DIR_ENV: &str = "AMCP_CREDENTIAL_STORE_DIR";

pub fn default_agent_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/AMCP/agent.sock"))
            .unwrap_or_else(|| PathBuf::from(".amcp/agent.sock"));
    }
    #[cfg(target_os = "windows")]
    {
        // Named pipes are not filesystem paths. Keeping the name in a
        // `PathBuf` preserves the existing CLI shape while the Agent and
        // Controller select the Windows named-pipe transport at compile time.
        return PathBuf::from(r"\\.\pipe\com.gohyperdev.amcp.agent");
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

/// Default Controller database location. This is kept separate from the
/// Agent's local runtime directory so a desktop Controller can use the same
/// catalog path as the CLI on every supported platform.
pub fn default_controller_db_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(|home| {
                PathBuf::from(home).join("Library/Application Support/AMCP/controller.sqlite")
            })
            .unwrap_or_else(|| PathBuf::from(".amcp/controller.sqlite"));
    }
    #[cfg(target_os = "windows")]
    {
        return env::var_os("LOCALAPPDATA")
            .map(|directory| PathBuf::from(directory).join("AMCP/controller.sqlite"))
            .unwrap_or_else(|| PathBuf::from("AMCP/controller.sqlite"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return env::var_os("XDG_STATE_HOME")
            .map(|directory| PathBuf::from(directory).join("AMCP/controller.sqlite"))
            .or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local/state/AMCP/controller.sqlite"))
            })
            .unwrap_or_else(|| PathBuf::from(".amcp/controller.sqlite"));
    }
    #[allow(unreachable_code)]
    PathBuf::from(".amcp/controller.sqlite")
}

pub fn default_agent_state_dir() -> PathBuf {
    default_agent_data_dir("agent-state")
}

pub fn default_agent_backup_dir() -> PathBuf {
    default_agent_data_dir("agent-backups")
}

fn default_agent_data_dir(leaf: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(|home| {
                PathBuf::from(home)
                    .join("Library/Application Support/AMCP")
                    .join(leaf)
            })
            .unwrap_or_else(|| PathBuf::from(".amcp").join(leaf));
    }
    #[cfg(target_os = "windows")]
    {
        return env::var_os("LOCALAPPDATA")
            .map(|directory| PathBuf::from(directory).join("AMCP").join(leaf))
            .unwrap_or_else(|| PathBuf::from("AMCP").join(leaf));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return env::var_os("XDG_STATE_HOME")
            .map(|directory| PathBuf::from(directory).join("AMCP").join(leaf))
            .or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local/state/AMCP").join(leaf))
            })
            .unwrap_or_else(|| PathBuf::from(".amcp").join(leaf));
    }
    #[allow(unreachable_code)]
    PathBuf::from(".amcp").join(leaf)
}

pub trait SecretStore {
    fn get(&self) -> Result<Option<String>>;
    fn set(&self, value: &str) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

/// Explicit file-backed credential store for platforms without a configured
/// native secret service. It is never selected implicitly: callers must set
/// `AMCP_CREDENTIAL_STORE_DIR` to a user-owned directory. On Unix, the store
/// enforces `0700` directory and `0600` credential files.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    pub fn for_account(directory: impl AsRef<Path>, account: &str) -> Result<Self> {
        let filename = account
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if filename.trim_matches('_').is_empty() {
            bail!("credential account must contain an alphanumeric character")
        }
        Ok(Self {
            path: directory.as_ref().join(format!("{filename}.credential")),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self) -> Result<Option<String>> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect AMCP file credential"),
        };
        if metadata.file_type().is_symlink() {
            bail!("AMCP credential file must not be a symlink")
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("AMCP credential file permissions must not grant group or other access")
        }
        Ok(Some(
            fs::read_to_string(&self.path)
                .context("read AMCP file credential")?
                .trim()
                .to_owned(),
        ))
    }

    fn set(&self, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            bail!("AMCP credential must not be empty")
        }
        let directory = self
            .path
            .parent()
            .context("credential path has no parent")?;
        fs::create_dir_all(directory).context("create AMCP credential store directory")?;
        #[cfg(unix)]
        fs::set_permissions(
            directory,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .context("restrict AMCP credential store directory")?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = self
            .path
            .with_extension(format!("{}-{timestamp}.tmp", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .context("create restricted AMCP credential")?;
            file.write_all(value.as_bytes())
                .context("write AMCP credential")?;
            file.sync_all().context("sync AMCP credential")?;
        }
        #[cfg(not(unix))]
        fs::write(&temporary, value).context("write AMCP credential")?;
        fs::rename(&temporary, &self.path).context("activate AMCP credential")?;
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("delete AMCP file credential"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacOsKeychain {
    pub service: String,
    pub account: String,
}

/// Per-user Windows Credential Manager store. The target name is namespaced
/// by the AMCP service and host account so credentials cannot be confused
/// between enrolled Agents.
#[derive(Debug, Clone)]
pub struct WindowsCredentialManager {
    pub target_name: String,
    pub account: String,
}

pub enum PlatformSecretStore {
    MacOsKeychain(MacOsKeychain),
    WindowsCredentialManager(WindowsCredentialManager),
    File(FileSecretStore),
}

impl SecretStore for PlatformSecretStore {
    fn get(&self) -> Result<Option<String>> {
        match self {
            Self::MacOsKeychain(store) => store.get(),
            Self::WindowsCredentialManager(store) => store.get(),
            Self::File(store) => store.get(),
        }
    }

    fn set(&self, value: &str) -> Result<()> {
        match self {
            Self::MacOsKeychain(store) => store.set(value),
            Self::WindowsCredentialManager(store) => store.set(value),
            Self::File(store) => store.set(value),
        }
    }

    fn delete(&self) -> Result<()> {
        match self {
            Self::MacOsKeychain(store) => store.delete(),
            Self::WindowsCredentialManager(store) => store.delete(),
            Self::File(store) => store.delete(),
        }
    }
}

pub fn credential_store_for_account(account: impl Into<String>) -> Result<PlatformSecretStore> {
    let account = account.into();
    #[cfg(target_os = "macos")]
    {
        Ok(PlatformSecretStore::MacOsKeychain(MacOsKeychain::new(
            account,
        )))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(PlatformSecretStore::WindowsCredentialManager(
            WindowsCredentialManager::new(account),
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let directory = env::var_os(CREDENTIAL_STORE_DIR_ENV).context(format!(
            "{CREDENTIAL_STORE_DIR_ENV} is required for credential persistence on this platform"
        ))?;
        Ok(PlatformSecretStore::File(FileSecretStore::for_account(
            PathBuf::from(directory),
            &account,
        )?))
    }
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

impl WindowsCredentialManager {
    pub fn new(account: impl Into<String>) -> Self {
        let account = account.into();
        Self {
            target_name: format!("{KEYCHAIN_SERVICE}:{account}"),
            account,
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

#[cfg(target_os = "windows")]
impl SecretStore for WindowsCredentialManager {
    fn get(&self) -> Result<Option<String>> {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW},
        };

        let mut target = wide_null(&self.target_name)?;
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: target is NUL-terminated and credential points to writable
        // storage. Windows allocates the returned credential, which is freed
        // with CredFree after copying the bounded blob.
        let found =
            unsafe { CredReadW(target.as_mut_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
        if found == 0 {
            // SAFETY: GetLastError reads the calling thread's last Win32 error.
            let error = unsafe { GetLastError() };
            if error == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(std::io::Error::from_raw_os_error(error as i32))
                .context("read AMCP credential from Windows Credential Manager");
        }
        if credential.is_null() {
            bail!("Windows Credential Manager returned an empty credential pointer")
        }
        // SAFETY: CredReadW succeeded and returned a valid CREDENTIALW. The
        // blob pointer/length are copied before freeing the credential.
        let bytes = unsafe {
            let value = &*credential;
            if value.CredentialBlob.is_null() {
                CredFree(credential.cast());
                bail!("Windows Credential Manager returned an invalid credential blob")
            }
            let bytes =
                std::slice::from_raw_parts(value.CredentialBlob, value.CredentialBlobSize as usize)
                    .to_vec();
            CredFree(credential.cast());
            bytes
        };
        let value = String::from_utf8(bytes).context("decode AMCP Windows credential")?;
        if value.trim().is_empty() {
            bail!("Windows Credential Manager returned an empty AMCP credential")
        }
        Ok(Some(value))
    }

    fn set(&self, value: &str) -> Result<()> {
        use windows_sys::Win32::{
            Foundation::FILETIME,
            Security::Credentials::{
                CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
            },
        };

        if value.trim().is_empty() || value.contains('\0') {
            bail!("AMCP credential must be non-empty and cannot contain NUL")
        }
        if value.len() > 2_560 {
            bail!("AMCP credential exceeds Windows Credential Manager blob limit")
        }
        let mut target = wide_null(&self.target_name)?;
        let mut username = wide_null(&self.account)?;
        let mut blob = value.as_bytes().to_vec();
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: username.as_mut_ptr(),
        };
        // SAFETY: all wide strings are NUL-terminated and the credential/blob
        // live until CredWriteW returns.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("store AMCP credential in Windows Credential Manager");
        }
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW},
        };

        let mut target = wide_null(&self.target_name)?;
        // SAFETY: target is a NUL-terminated Windows string.
        if unsafe { CredDeleteW(target.as_mut_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: GetLastError reads the calling thread's last Win32 error.
            let error = unsafe { GetLastError() };
            if error == ERROR_NOT_FOUND {
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(error as i32))
                .context("delete AMCP credential from Windows Credential Manager");
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Result<Vec<u16>> {
    if value.contains('\0') {
        bail!("Windows credential identifier cannot contain NUL")
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

#[cfg(not(target_os = "windows"))]
impl SecretStore for WindowsCredentialManager {
    fn get(&self) -> Result<Option<String>> {
        bail!("Windows Credential Manager is unavailable on this platform")
    }

    fn set(&self, _value: &str) -> Result<()> {
        bail!("Windows Credential Manager is unavailable on this platform")
    }

    fn delete(&self) -> Result<()> {
        bail!("Windows Credential Manager is unavailable on this platform")
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

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

    #[test]
    fn default_controller_database_path_is_user_scoped() {
        let path = default_controller_db_path();
        assert!(path.is_absolute() || path.starts_with(".amcp") || path.starts_with("AMCP"));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("controller.sqlite")
        );
    }

    #[test]
    fn default_agent_data_paths_are_distinct_and_user_scoped() {
        let state = default_agent_state_dir();
        let backups = default_agent_backup_dir();
        assert_ne!(state, backups);
        assert_eq!(
            state.file_name().and_then(|name| name.to_str()),
            Some("agent-state")
        );
        assert_eq!(
            backups.file_name().and_then(|name| name.to_str()),
            Some("agent-backups")
        );
    }

    #[test]
    fn file_credential_store_round_trips_and_deletes_a_host_credential() {
        let directory = tempdir().expect("credential directory");
        let store = FileSecretStore::for_account(directory.path(), "agent:host-a")
            .expect("file credential store");
        assert!(store.get().expect("empty credential store").is_none());
        store.set("credential-a").expect("store credential");
        assert_eq!(
            store.get().expect("read credential"),
            Some("credential-a".into())
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(store.path())
                .expect("credential metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        #[cfg(unix)]
        {
            std::fs::set_permissions(
                store.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o640),
            )
            .expect("broaden credential permissions");
            assert!(store.get().is_err());
            store
                .set("credential-a")
                .expect("repair credential permissions");
        }
        store.delete().expect("delete credential");
        assert!(store.get().expect("empty credential store").is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_credential_manager_round_trips_a_host_credential() {
        let store = WindowsCredentialManager::new(format!(
            "agent:amcp-platform-test-{}",
            std::process::id()
        ));
        store.delete().expect("clear stale test credential");
        store
            .set("amcp-test-credential")
            .expect("store Credential Manager credential");
        assert_eq!(
            store.get().expect("read Credential Manager credential"),
            Some("amcp-test-credential".into())
        );
        store
            .delete()
            .expect("delete Credential Manager credential");
        assert!(
            store
                .get()
                .expect("verify Credential Manager deletion")
                .is_none()
        );
    }
}
