//! Native OS credential store adapter implementing [`SecretStore`] via `keyring`.

use std::sync::Arc;

use async_trait::async_trait;
use keyring::{Entry, Error as KeyringError};
use parking_lot::Mutex;
use zeroize::Zeroizing;
use zerovault_types::{SecretStore, ZeroVaultError, ZeroVaultResult};

/// OS credential vault adapter backed by `keyring::Entry`.
///
/// Bridges synchronous/blocking platform stores (Windows Credential Manager,
/// Linux `keyutils` / Secret Service D-Bus, macOS Keychain) into Tokio using
/// [`tokio::task::spawn_blocking`] and serializes accesses to avoid concurrent
/// OS credential-store races.
#[derive(Debug, Clone, Default)]
pub struct OsKeyringSecretStore {
    op_lock: Arc<Mutex<()>>,
}

impl OsKeyringSecretStore {
    /// Creates a new [`OsKeyringSecretStore`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn map_keyring_err(err: KeyringError) -> ZeroVaultError {
    ZeroVaultError::KeyringError(err.to_string())
}

#[async_trait]
impl SecretStore for OsKeyringSecretStore {
    async fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> ZeroVaultResult<()> {
        let service_owned = service.to_owned();
        let account_owned = account.to_owned();
        let secret_owned = Zeroizing::new(secret.to_vec());
        let lock = Arc::clone(&self.op_lock);

        tokio::task::spawn_blocking(move || {
            let _guard = lock.lock();
            let entry = Entry::new(&service_owned, &account_owned).map_err(map_keyring_err)?;
            entry.set_secret(&secret_owned).map_err(map_keyring_err)
        })
        .await
        .map_err(|e| ZeroVaultError::KeyringError(format!("keyring blocking task failed: {e}")))?
    }

    async fn get_secret(
        &self,
        service: &str,
        account: &str,
    ) -> ZeroVaultResult<Option<Zeroizing<Vec<u8>>>> {
        let service_owned = service.to_owned();
        let account_owned = account.to_owned();
        let lock = Arc::clone(&self.op_lock);

        tokio::task::spawn_blocking(move || {
            let _guard = lock.lock();
            let entry = Entry::new(&service_owned, &account_owned).map_err(map_keyring_err)?;
            match entry.get_secret() {
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(KeyringError::NoEntry) => Ok(None),
                Err(err) => Err(map_keyring_err(err)),
            }
        })
        .await
        .map_err(|e| ZeroVaultError::KeyringError(format!("keyring blocking task failed: {e}")))?
    }

    async fn delete_secret(&self, service: &str, account: &str) -> ZeroVaultResult<()> {
        let service_owned = service.to_owned();
        let account_owned = account.to_owned();
        let lock = Arc::clone(&self.op_lock);

        tokio::task::spawn_blocking(move || {
            let _guard = lock.lock();
            let entry = Entry::new(&service_owned, &account_owned).map_err(map_keyring_err)?;
            match entry.delete_credential() {
                Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
                Err(err) => Err(map_keyring_err(err)),
            }
        })
        .await
        .map_err(|e| ZeroVaultError::KeyringError(format!("keyring blocking task failed: {e}")))?
    }
}
