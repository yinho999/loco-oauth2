#![allow(clippy::unused_async)]

use axum::{extract::Query, response::Redirect, Extension};
use axum_session::{Session, SessionNullPool};
use loco_oauth2::{middleware::private_cookie_jar::OAuth2PrivateCookieJar, OAuth2ClientStore};
use loco_rs::prelude::*;
use serde::Deserialize;

use crate::{
    controllers::middleware::auth::{
        create_short_live_cookie_with_token_response, OAuth2CookieUser,
    },
    models::{o_auth2_sessions, users, users::OAuth2UserProfile},
};

#[derive(Debug, Deserialize)]
pub struct AuthParams {
    code: String,
    state: String,
}

/// The authorization URL for the `OAuth2` flow
/// This will redirect the user to the `OAuth2` provider's login page
/// and then to the callback URL
/// # Arguments
/// * `session` - The axum session
/// * `oauth_store` - The `OAuth2ClientStore` extension
/// # Returns
/// The HTML response with the link to the `OAuth2` provider's login page
/// # Errors
/// `loco_rs::errors::Error` - When the `OAuth2` client cannot be retrieved
pub async fn authorization_url(
    session: Session<SessionNullPool>,
    Extension(oauth2_store): Extension<OAuth2ClientStore>,
) -> Result<String> {
    let (auth_url, csrf_token) = oauth2_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?
        .get_authorization_url();
    session.set("CSRF_TOKEN", csrf_token.secret().to_owned());
    Ok(auth_url.to_string())
}

/// The callback URL for the `OAuth2` flow
/// This will exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie Lastly, it will redirect the user to the protected URL
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `jar` - The oauth2 private cookie jar
/// * `oauth_store` - The `OAuth2ClientStore` extension
/// # Returns
/// The response with the short live cookie and the redirect to the protected
/// URL # Errors
/// `loco_rs::errors::Error`
async fn google_callback(
    State(ctx): State<AppContext>,
    session: Session<SessionNullPool>,
    Query(params): Query<AuthParams>,
    // Extract the private cookie jar from the request
    jar: OAuth2PrivateCookieJar,
    Extension(oauth_store): Extension<OAuth2ClientStore>,
) -> Result<impl IntoResponse> {
    let mut client = oauth_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?;
    // Get the CSRF token from the session
    let csrf_token = session
        .get::<String>("CSRF_TOKEN")
        .ok_or_else(|| Error::BadRequest("CSRF token not found".to_string()))?;
    // Exchange the code with a token
    let (token, profile) = client
        .verify_code_from_callback(params.code, params.state, csrf_token)
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    // Get the user profile
    let profile = profile.json::<OAuth2UserProfile>().await.unwrap();
    let user = users::Model::upsert_with_oauth(&ctx.db, &profile)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating user");
            Error::InternalServerError
        })?;
    o_auth2_sessions::Model::upsert_with_oauth(&ctx.db, &token, &user)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating session");
            Error::InternalServerError
        })?;
    let oauth2_cookie_config = client.get_cookie_config();
    let jar = create_short_live_cookie_with_token_response(oauth2_cookie_config, &token, jar)
        .map_err(|_e| Error::InternalServerError)?;
    let protect_url = oauth2_cookie_config
        .protected_url
        .clone()
        .unwrap_or_else(|| "/oauth2/protected".to_string());
    drop(client);
    let response = (jar, Redirect::to(&protect_url)).into_response();
    tracing::info!("response: {:?}", response);
    Ok(response)
}

async fn protected(user: OAuth2CookieUser) -> Result<impl IntoResponse> {
    let user = user.as_ref();
    Ok("You are protected! Email: ".to_string() + &user.email)
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("oauth2")
        .add("/", get(authorization_url))
        .add("/google/callback", get(google_callback))
        .add("/protected", get(protected))
}
