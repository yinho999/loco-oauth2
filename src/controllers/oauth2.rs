#![allow(clippy::unused_async)]

use crate::OAuth2ClientStore;
use axum::{extract::Query, response::Redirect, Extension};
use axum_session::{DatabasePool, Session};
use loco_rs::prelude::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fmt::Debug;
use tokio::sync::MutexGuard;

use crate::controllers::middleware::OAuth2PrivateCookieJarTrait;
use crate::controllers::middleware::{OAuth2CookieUser, OAuth2PrivateCookieJar};
use crate::grants::authorization_code::GrantTrait;
use crate::models::oauth2_sessions::OAuth2SessionsTrait;
use crate::models::users::OAuth2UserTrait;

#[derive(Debug, Deserialize)]
pub struct AuthParams {
    code: String,
    state: String,
}

/// Helper function to get the authorization URL and save the CSRF token in the session
///
/// # Generics
/// * `T` - The database pool
/// # Arguments
/// * `session` - The axum session
/// * `oauth2_client` - The `AuthorizationCodeGrant` client
/// # Returns
/// * `String` - The authorization URL
pub async fn get_authorization_url<T: DatabasePool + Clone + Debug + Sync + Send + 'static>(
    session: Session<T>,
    oauth2_client: &mut MutexGuard<'_, dyn GrantTrait>,
) -> String {
    let (auth_url, csrf_token) = oauth2_client.get_authorization_url();
    session.set("CSRF_TOKEN", csrf_token.secret().to_owned());
    auth_url.to_string()
}

/// Helper function to exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie
///
/// Lastly, it will redirect the user to the protected URL
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// * `W` - The database pool
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `jar` - The oauth2 private cookie jar
/// * `client` - The `AuthorizationCodeGrant` client
/// # Returns
/// * `Result<impl IntoResponse>` - The response with the short live cookie and the redirect to the protected URL
/// # Errors
/// * `loco_rs::errors::Error`
pub async fn callback<
    T: DeserializeOwned + Send,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U>,
    W: DatabasePool + Clone + Debug + Sync + Send + 'static,
>(
    ctx: AppContext,
    session: Session<W>,
    params: AuthParams,
    // Extract the private cookie jar from the request
    jar: OAuth2PrivateCookieJar,
    client: &mut MutexGuard<'_, dyn GrantTrait>,
) -> Result<impl IntoResponse> {
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
    let profile = profile.json::<T>().await.map_err(|e| {
        tracing::error!("Error getting profile: {:?}", e);
        Error::InternalServerError
    })?;
    let user = U::upsert_with_oauth(&ctx.db, &profile)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating user");
            Error::InternalServerError
        })?;
    V::upsert_with_oauth2(&ctx.db, &token, &user)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating session");
            Error::InternalServerError
        })?;
    let oauth2_cookie_config = client.get_cookie_config();
    let jar = OAuth2PrivateCookieJar::create_short_live_cookie_with_token_response(
        oauth2_cookie_config,
        &token,
        jar,
    )
    .map_err(|_e| Error::InternalServerError)?;
    let protect_url = oauth2_cookie_config
        .protected_url
        .clone()
        .unwrap_or_else(|| "/oauth2/protected".to_string());
    let response = (jar, Redirect::to(&protect_url)).into_response();
    tracing::info!("response: {:?}", response);
    Ok(response)
}

/// Helper function to exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie
///
/// Lastly, it will redirect the user to the protected URL
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// * `W` - The database pool
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `client` - The `AuthorizationCodeGrant` client
/// # Returns
/// * `Result<U>` - The user
/// # Errors
/// * `loco_rs::errors::Error`
pub async fn callback_jwt<
    T: DeserializeOwned + Send,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U>,
    W: DatabasePool + Clone + Debug + Sync + Send + 'static,
>(
    ctx: &AppContext,
    session: Session<W>,
    params: AuthParams,
    client: &mut MutexGuard<'_, dyn GrantTrait>,
) -> Result<U> {
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
    let profile = profile.json::<T>().await.map_err(|e| {
        tracing::error!("Error getting profile: {:?}", e);
        Error::InternalServerError
    })?;
    let user = U::upsert_with_oauth(&ctx.db, &profile)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating user");
            Error::InternalServerError
        })?;
    V::upsert_with_oauth2(&ctx.db, &token, &user)
        .await
        .map_err(|_e| {
            tracing::error!("Error creating session");
            Error::InternalServerError
        })?;

    Ok(user)
}

/// The authorization URL for the `OAuth2` flow
///
/// This will redirect the user to the `OAuth2` provider's login page
/// and then to the callback URL
/// # Generics
/// * `T` - The database pool
/// # Arguments
/// * `session` - The axum session
/// * `oauth2_store` - The `OAuth2ClientStore` extension
/// # Returns
/// The HTML response with the link to the `OAuth2` provider's login page
/// # Errors
/// `loco_rs::errors::Error` - When the `OAuth2` client cannot be retrieved
pub async fn google_authorization_url<T: DatabasePool + Clone + Debug + Sync + Send + 'static>(
    session: Session<T>,
    Extension(oauth2_store): Extension<OAuth2ClientStore>,
) -> Result<String> {
    let mut client = oauth2_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?;
    let auth_url = get_authorization_url(session, &mut client).await;
    drop(client);
    Ok(auth_url)
}

/// The callback URL for the `OAuth2` flow
///
/// This will exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie
///
/// Lastly, it will redirect the user to the protected URL
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// * `W` - The database pool
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `jar` - The oauth2 private cookie jar
/// * `oauth2_store` - The `OAuth2ClientStore` extension
/// # Returns
/// The response with the short live cookie and the redirect to the protected
/// URL
/// # Errors
/// * `loco_rs::errors::Error`
pub async fn google_callback_cookie<
    T: DeserializeOwned + Send,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U>,
    W: DatabasePool + Clone + Debug + Sync + Send + 'static,
>(
    State(ctx): State<AppContext>,
    session: Session<W>,
    Query(params): Query<AuthParams>,
    // Extract the private cookie jar from the request
    jar: OAuth2PrivateCookieJar,
    Extension(oauth2_store): Extension<OAuth2ClientStore>,
) -> Result<impl IntoResponse> {
    let mut client = oauth2_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?;
    let response = callback::<T, U, V, W>(ctx, session, params, jar, &mut client).await?;
    drop(client);
    Ok(response)
}

/// The callback URL for the `OAuth2` flow
///
/// This will exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie.
///
/// Lastly, it will redirect the user to the protected URL
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// * `W` - The database pool
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `oauth2_store` - The `OAuth2ClientStore` extension
/// # Return
/// * `Result<impl IntoResponse>` - The response with the jwt token
/// # Errors
/// * `loco_rs::errors::Error`
pub async fn google_callback_jwt<
    T: DeserializeOwned + Send,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U>,
    W: DatabasePool + Clone + Debug + Sync + Send + 'static,
>(
    State(ctx): State<AppContext>,
    session: Session<W>,
    Query(params): Query<AuthParams>,
    Extension(oauth2_store): Extension<OAuth2ClientStore>,
) -> Result<impl IntoResponse> {
    let mut client = oauth2_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?;
    let jwt_secret = ctx.config.get_jwt_config()?;
    let user = callback_jwt::<T, U, V, W>(&ctx, session, params, &mut client).await?;
    drop(client);
    let token = user
        .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;
    Ok(token)
}

/// The protected URL for the `OAuth2` flow
/// This will return a message indicating that the user is protected
///
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// # Arguments
/// * `user` - The `OAuth2CookieUser` that holds the user and the session
/// # Returns
/// The response with the message indicating that the user is protected
/// # Errors
/// * `loco_rs::errors::Error` - When the user cannot be retrieved
pub async fn protected<
    T: DeserializeOwned + Send,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U> + ModelTrait,
>(
    user: OAuth2CookieUser<T, U, V>,
) -> Result<impl IntoResponse> {
    let _user = user.as_ref();
    Ok("You are protected!".to_string())
}
