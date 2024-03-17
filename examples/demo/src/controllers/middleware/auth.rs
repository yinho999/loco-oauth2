use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::Response,
    Extension, RequestPartsExt,
};
use loco_oauth2::{
    basic::BasicTokenResponse, grants::authorization_code::AuthorizationCodeCookieConfig,
    middleware::private_cookie_jar::OAuth2PrivateCookieJar, url, OAuth2ClientStore, TokenResponse,
};
use loco_rs::prelude::*;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};

use crate::models::{o_auth2_sessions, users};

const COOKIE_NAME: &str = "sid";

// Define a struct to represent user from session information serialized
// to/from JSON
#[derive(Debug, Deserialize, Serialize)]
pub struct OAuth2CookieUser {
    pub user: users::Model,
}

impl AsRef<users::Model> for OAuth2CookieUser {
    fn as_ref(&self) -> &users::Model {
        &self.user
    }
}

async fn validate_session_and_retrieve_user(
    db: &DatabaseConnection,
    cookie: &str,
) -> Result<users::Model> {
    // Check if the session id is expired or exists
    let expired = o_auth2_sessions::Model::is_expired(db, cookie)
        .await
        .map_err(|e| {
            tracing::info!("Cannot find cookie");
            Error::Unauthorized(e.to_string())
        })?;
    if expired {
        tracing::info!("Session expired");
        return Err(Error::Unauthorized("Session expired".to_string()));
    }
    users::Model::find_by_oauth2_session_id(db, cookie)
        .await
        .map_err(|e| {
            tracing::info!("Cannot find user");
            Error::Unauthorized(e.to_string())
        })
}

// Implement the FromRequestParts trait for the OAuthCookieUser struct
#[async_trait]
impl<S> FromRequestParts<S> for OAuth2CookieUser
where
    S: Send + Sync,
    AppContext: FromRef<S>,
{
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> core::result::Result<Self, Self::Rejection> {
        let state: AppContext = AppContext::from_ref(state);
        let Extension(store) = parts
            .extract::<Extension<OAuth2ClientStore>>()
            .await
            .map_err(loco_rs::prelude::IntoResponse::into_response)?;

        let jar = OAuth2PrivateCookieJar::from_headers(&parts.headers, store.key.clone());

        let cookie = jar
            .get(COOKIE_NAME)
            .map(|cookie| cookie.value().to_owned())
            .ok_or_else(|| {
                tracing::info!("Cannot get cookie");
                (StatusCode::UNAUTHORIZED, "Unauthorized!".to_string()).into_response()
            })?;
        let user = validate_session_and_retrieve_user(&state.db, &cookie)
            .await
            .map_err(|e| {
                tracing::info!("Cannot validate session");
                (StatusCode::UNAUTHORIZED, e.to_string()).into_response()
            })?;
        Ok(Self { user })
    }
}

/// Create a short live cookie with the token response
///
/// # Arguments
/// config - The authorization code config with the oauth2 authorization code
/// grant configuration token - The token response from the oauth2 authorization
/// code grant jar - The private cookie jar
///
/// # Returns
/// A result with the private cookie jar
///
/// # Errors
/// When url parsing fails
pub fn create_short_live_cookie_with_token_response(
    config: &AuthorizationCodeCookieConfig,
    token: &BasicTokenResponse,
    jar: OAuth2PrivateCookieJar,
) -> Result<OAuth2PrivateCookieJar> {
    // Set the cookie
    let secs: i64 = token
        .expires_in()
        .unwrap_or(std::time::Duration::new(0, 0))
        .as_secs()
        .try_into()
        .map_err(|_e| Error::InternalServerError)?;
    // domain
    let protected_url = config
        .protected_url
        .clone()
        .unwrap_or_else(|| "http://localhost:3000/oauth2/protected".to_string());
    let protected_url = url::Url::parse(&protected_url).map_err(|_e| Error::InternalServerError)?;
    let protected_domain = protected_url.domain().unwrap_or("localhost");
    let protected_path = protected_url.path();
    // Create the cookie with the session id, domain, path, and secure flag from
    // the token and profile
    let cookie = cookie::Cookie::build((COOKIE_NAME, token.access_token().secret().to_owned()))
        .domain(protected_domain.to_owned())
        .path(protected_path.to_owned())
        // secure flag is for https - https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.1
        .secure(true)
        // Restrict access in the client side code to prevent XSS attacks
        .http_only(true)
        .max_age(time::Duration::seconds(secs));
    Ok(jar.add(cookie))
}
