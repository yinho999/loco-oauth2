#![allow(elided_lifetimes_in_paths)]
use crate::oauth2_grant::OAuth2ClientGrantEnum;
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod config;
pub mod controllers;
pub mod error;
pub mod grants;
pub mod migration;
pub mod models;
pub mod oauth2_grant;

const COOKIE_NAME: &str = "sid";
use crate::config::Config;
use crate::error::{OAuth2ClientResult, OAuth2StoreError, OAuth2StoreResult};
use crate::grants::authorization_code::{Client, GrantTrait};
pub use oauth2 as base_oauth2;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone)]
pub struct OAuth2ClientStore {
    clients: BTreeMap<String, OAuth2ClientGrantEnum>,
    pub key: Key,
}

impl OAuth2ClientStore {
    /// Create a new instance of `OAuth2ClientStore`.
    /// # Arguments
    /// * `config` - An instance of `OAuth2Config` that holds the `OAuth2` configuration.
    ///
    /// # Returns
    /// * `Self` - An instance of `OAuth2ClientStore`.
    ///
    /// # Errors
    /// * `OAuth2StoreError` - An error indicating the failure to create the `OAuth2ClientStore`.
    pub fn new(config: Config) -> OAuth2StoreResult<Self> {
        let mut clients = BTreeMap::new();
        Self::insert_authorization_code_clients(&mut clients, config.authorization_code)?;
        let key = match config.secret_key {
            Some(key) => Key::try_from(&key[..])?,
            None => Key::generate(),
        };
        Ok(Self { clients, key })
    }

    /// Insert Authorization Code Grant client into the store.
    ///
    /// # Arguments
    /// `clients` - A BTreeMap that holds the client id and `OAuth2ClientGrantEnum`.
    /// `authorization_code` - A vector of `AuthorizationCodeConfig` that holds the client configuration.
    #[tracing::instrument(
        name = "Insert Authorization Code Grant client",
        skip(clients, authorization_code)
    )]
    fn insert_authorization_code_clients(
        clients: &mut BTreeMap<String, OAuth2ClientGrantEnum>,
        authorization_code: Vec<config::AuthorizationCode>,
    ) -> OAuth2ClientResult<()> {
        for grant in authorization_code {
            tracing::info!(
                "Creating Authorization Code Grant client: {:?}",
                grant.client_identifier
            );
            let client = Client::new(
                grant.client_credentials,
                grant.url_config,
                grant.cookie_config,
                None,
            )?;
            tracing::info!(
                "Inserting Authorization Code Grant client: {:?}",
                grant.client_identifier
            );
            clients.insert(
                grant.client_identifier,
                OAuth2ClientGrantEnum::AuthorizationCode(Arc::new(Mutex::new(client))),
            );
        }
        Ok(())
    }

    /// Get client by its id.
    ///
    /// # Arguments
    /// * `id` - A string slice that holds the client id.
    fn get<T: AsRef<str>>(&self, id: &T) -> Option<&OAuth2ClientGrantEnum> {
        self.clients.get(id.as_ref())
    }
    /// Get Authorization Code Grant client by its id.
    ///
    /// # Arguments
    /// * `id` - A string slice that holds the client id.
    ///
    /// # Returns
    /// * `OAuth2StoreResult<&AuthorizationCodeClient>` - A result that holds a reference to the `AuthorizationCodeClient` if found, otherwise an `OAuth2StoreError`.
    #[tracing::instrument(name = "Get Authorization Code Grant client", skip(self))]
    pub async fn get_authorization_code_client<T: AsRef<str> + std::fmt::Debug + Send>(
        &self,
        client_identifier: T,
    ) -> OAuth2StoreResult<MutexGuard<'_, dyn GrantTrait>> {
        match self.get(&client_identifier) {
            Some(OAuth2ClientGrantEnum::AuthorizationCode(client)) => {
                let client = client.lock().await;
                Ok(client)
            }
            Some(client) => Err(OAuth2StoreError::ClientTypeMismatch(
                client_identifier.as_ref().to_string(),
                client.clone(),
            )),
            None => Err(OAuth2StoreError::ClientNotFound),
        }
    }
}
// this impl tells `SignedCookieJar` how to access the key from our state
impl FromRef<OAuth2ClientStore> for Key {
    fn from_ref(store: &OAuth2ClientStore) -> Self {
        store.key.clone()
    }
}
