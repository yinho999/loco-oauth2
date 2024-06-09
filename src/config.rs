use crate::error::OAuth2StoreError;
use crate::grants::authorization_code::{CookieConfig, Credentials, UrlConfig};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

/// `OAuth2 Authentication configuration`
/// # Fields
/// * `secret_key` - Optional, key for Private Cookie Jar, must be more than 64 bytes. If not provided, a new key will be generated.
/// * `authorization_code` - Authorization code grant type
///
/// Example (development):
/// ```yaml
/// # config/development.yaml
/// oauth2:
///  secret_key: {{get_env(name="OAUTH_PRIVATE_KEY", default="144, 76, 183, 1, 15, 184, 233, 174, 214, 251, 190, 186, 122, 61, 74, 84, 225, 110, 189, 115, 10, 251, 133, 128, 52, 46, 15, 66, 85, 1, 245, 73, 27, 113, 189, 15, 209, 205, 61, 100, 73, 31, 18, 58, 235, 105, 141, 36, 70, 92, 231, 151, 27, 32, 243, 117, 30, 244, 110, 89, 233, 196, 137, 130")}} # Optional, key for Private Cookie Jar, must be more than 64 bytes. If not provided, a new key will be generated.
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
pub struct Config {
    pub secret_key: Option<Vec<u8>>,
    pub authorization_code: Vec<AuthorizationCode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationCode {
    pub client_identifier: String,
    pub client_credentials: Credentials,
    pub url_config: UrlConfig,
    pub cookie_config: CookieConfig,
    pub timeout_seconds: Option<u64>,
}

impl TryFrom<Value> for Config {
    type Error = OAuth2StoreError;
    #[tracing::instrument(name = "Convert Value to OAuth2Config")]
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let secret_key: Option<Vec<u8>> =
            value.get("secret_key").and_then(|v| v.as_str()).map(|s| {
                s.split(", ")
                    .filter_map(|byte| u8::from_str(byte.trim()).ok())
                    .collect()
            });

        let authorization_code: Vec<AuthorizationCode> = value
            .get("authorization_code")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                serde_json::Error::custom("authorization_code is not an array or is missing")
            })
            .and_then(|v| {
                v.iter()
                    .map(|item| serde_json::from_value(item.clone()))
                    .collect()
            })?;
        Ok(Self {
            secret_key,
            authorization_code,
        })
    }
}
