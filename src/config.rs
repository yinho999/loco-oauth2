use crate::error::OAuth2StoreError;
use crate::grants::authorization_code::{
    AuthorizationCodeCookieConfig, AuthorizationCodeCredentials, AuthorizationCodeUrlConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// OAuth2 Authentication configuration
///
/// Example (development):
/// ```yaml
/// # config/development.yaml
/// oauth2:
///  authorization_code: # Authorization code grant type
///   - client_identifier: google # Identifier for the OAuth2 provider. Replace 'google' with your provider's name if different, must be unique within the oauth2 config.
///     client_credentials:
///       client_id: <your client id> # Replace with your OAuth2 client ID.
///       client_secret: <your client secret> # Replace with your OAuth2 client secret.
///     url_config:
///      auth_url: https://accounts.google.com/o/oauth2/auth # authorization endpoint from the provider
///      token_url: https://www.googleapis.com/oauth2/v3/token # token endpoint from the provider for exchanging the authorization code for an access token
///      redirect_url: http://localhost:3000/api/auth/google_callback # server callback endpoint for the provider
///      profile_url: https://openidconnect.googleapis.com/v1/userinfo # user profile endpoint from the provider for getting user data
///      scopes:
///       - https://www.googleapis.com/auth/userinfo.email # Scopes for requesting access to user data
///     cookie_config:
///       protected_url: http://localhost:3000/api/auth/google_callback # Optional - For redirecting to protect url in cookie to prevent XSS attack
///     timeout_seconds: 600 # Optional, default 600 seconds
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuth2Config {
    pub authorization_code: Vec<AuthorizationCodeConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationCodeConfig {
    pub client_identifier: String,
    pub client_credentials: AuthorizationCodeCredentials,
    pub url_config: AuthorizationCodeUrlConfig,
    pub cookie_config: AuthorizationCodeCookieConfig,
    pub timeout_seconds: Option<u64>,
}

impl TryFrom<Value> for OAuth2Config {
    type Error = OAuth2StoreError;
    #[tracing::instrument(name = "Convert Value to OAuth2Config")]
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let config: OAuth2Config = serde_json::from_value(value)?;
        Ok(config)
    }
}
