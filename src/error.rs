use oauth2::{
    basic::BasicErrorResponseType, url::ParseError, RequestTokenError, StandardErrorResponse,
};

#[allow(clippy::module_name_repetitions)]
#[derive(thiserror::Error, Debug)]
pub enum OAuth2StoreError {
    /// Error for client not found within the store
    #[error("Client not found")]
    ClientNotFound,
    
    /// Error parsing from configuration JSON to OAuth2 configuration
    #[error("Cannot parse JSON for OAuth2 configuration: {0}")]
    ConfigJsonError(#[from] serde_json::Error),
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
}

type BasicTokenError = RequestTokenError<
    oauth2::reqwest::Error<reqwest::Error>,
    StandardErrorResponse<BasicErrorResponseType>,
>;

pub type OAuth2ClientResult<T> = std::result::Result<T, OAuth2ClientError>;
pub type OAuth2StoreResult<T> = std::result::Result<T, OAuth2StoreError>;