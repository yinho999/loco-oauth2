use crate::oauth2_grant::OAuth2ClientGrantEnum;
use std::collections::BTreeMap;

pub mod config;
pub mod error;
pub mod grants;
pub mod oauth2_grant;

pub use oauth2::*;
use crate::error::{OAuth2StoreError, OAuth2StoreResult};
use crate::grants::authorization_code::AuthorizationCodeClient;

#[derive(Clone)]
pub struct OAuth2ClientStore {
    pub clients: BTreeMap<String, OAuth2ClientGrantEnum>,
}

impl OAuth2ClientStore {
    /// Create a new instance of `OAuth2ClientStore`.
    #[must_use]
    pub fn new(clients: BTreeMap<String, OAuth2ClientGrantEnum>) -> Self {
        Self { clients }
    }

    /// Get Authorization Code Grant client by its id.
    /// 
    /// # Arguments
    /// * `id` - A string slice that holds the client id.
    /// 
    /// # Returns
    /// * `OAuth2StoreResult<&AuthorizationCodeClient>` - A result that holds a reference to the `AuthorizationCodeClient` if found, otherwise an `OAuth2StoreError`.
    pub fn get_authorization_code_client<T:AsRef<str>>(&self, id: T) -> OAuth2StoreResult<&AuthorizationCodeClient> {
        match self.get(id) {
            Some(OAuth2ClientGrantEnum::AuthorizationCode(client)) => Ok(client),
            _ => Err(OAuth2StoreError::ClientNotFound),
        }
    }
    
    
}
