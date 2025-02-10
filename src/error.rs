use crate::oauth2_grant::OAuth2ClientGrantEnum;
use oauth2::basic::{BasicErrorResponseType};
use oauth2::{url::ParseError, HttpClientError, RequestTokenError, StandardErrorResponse};
use std::fmt::{Debug, Display};
use reqwest::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(thiserror::Error)]
pub enum OAuth2StoreError {
    /// Error for client not found within the store
    ClientNotFound,
    /// Error for client already exists but different `OAuth2ClientGrantEnum`
    ClientTypeMismatch(String, OAuth2ClientGrantEnum),
    /// Error parsing from configuration JSON to `OAuth2` configuration
    ConfigJson(#[from] serde_json::Error),
    /// Error for client creation
    ClientCreation(#[from] OAuth2ClientError),
    /// Error for converting key from `[u8]` to `Key`
    KeyConversion(#[from] cookie::KeyError),
}

impl OAuth2StoreError {
    /// Print the error message
    fn message(&self) -> String {
        match self {
            Self::ClientNotFound => "Client not found".to_string(),
            Self::ClientTypeMismatch(credential_identifier, client) => match client {
                OAuth2ClientGrantEnum::AuthorizationCode(_) => {
                    format!("Authorization Code client already exists with credential identifier: {credential_identifier}", )
                }
                OAuth2ClientGrantEnum::ClientCredentials => {
                    format!("Client Credentials client already exists with credential identifier: {credential_identifier}", )
                }
                OAuth2ClientGrantEnum::DeviceCode => format!("Device Code client already exists with credential identifier: {credential_identifier}", ),
                OAuth2ClientGrantEnum::Implicit => format!("Implicit client already exists with credential identifier: {credential_identifier}", ),
                OAuth2ClientGrantEnum::ResourceOwnerPasswordCredentials => format!(
                    "Resource Owner Password Credentials client already exists with credential identifier: {credential_identifier}", 
                ),
            },
            Self::ConfigJson(err) => format!("Cannot parse JSON for OAuth2 configuration: {err}", ),
            Self::ClientCreation(err) => format!("Error creating client: {err}", ),
            Self::KeyConversion(err) => format!("Error converting key: {err}", ),
        }
    }
}

impl Debug for OAuth2StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}
impl Display for OAuth2StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}
#[allow(clippy::module_name_repetitions)]
#[derive(thiserror::Error, Debug)]
pub enum OAuth2ClientError {
    #[error(transparent)]
    UrlError(#[from] ParseError),
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error(transparent)]
    BasicTokenError(#[from] BasicTokenError),
    #[error("CSRF token error")]
    CsrfTokenError,
    #[error("Profile error")]
    ProfileError(reqwest::Error),
    #[error("Configuration error")]
    ConfigError(#[from] oauth2::ConfigurationError),
}

type BasicTokenError = RequestTokenError<
    HttpClientError<Error>,
    StandardErrorResponse<BasicErrorResponseType>,
>;

pub type OAuth2ClientResult<T> = std::result::Result<T, OAuth2ClientError>;
pub type OAuth2StoreResult<T> = std::result::Result<T, OAuth2StoreError>;
