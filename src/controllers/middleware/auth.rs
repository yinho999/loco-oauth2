use crate::controllers::models::oauth2_sessions::OAuth2SessionsTrait;
use crate::controllers::models::users::OAuth2UserTrait;
use crate::{middleware::OAuth2PrivateCookieJar, OAuth2ClientStore, COOKIE_NAME};
use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::Response,
    Extension, RequestPartsExt,
};
use loco_rs::prelude::*;
use sea_orm::DatabaseConnection;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

// Define a struct to represent user from session information serialized
// to/from JSON
#[derive(Debug, Deserialize, Serialize)]
pub struct OAuth2CookieUser<
    T: DeserializeOwned,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U> + ModelTrait,
> {
    pub user: U,
    _marker: PhantomData<T>,
    _marker2: PhantomData<V>,
}

impl<
        T: DeserializeOwned,
        U: OAuth2UserTrait<T> + ModelTrait,
        V: OAuth2SessionsTrait<U> + ModelTrait,
    > AsRef<U> for OAuth2CookieUser<T, U, V>
{
    fn as_ref(&self) -> &U {
        &self.user
    }
}
impl<T, U, V> OAuth2CookieUser<T, U, V>
where
    T: DeserializeOwned,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U> + ModelTrait,
{
    async fn validate_session_and_retrieve_user(
        db: &DatabaseConnection,
        cookie: &str,
    ) -> Result<U> {
        // Check if the session id is expired or exists
        let expired = V::is_expired(db, cookie).await.map_err(|e| {
            tracing::info!("Cannot find cookie");
            Error::Unauthorized(e.to_string())
        })?;
        if expired {
            tracing::info!("Session expired");
            return Err(Error::Unauthorized("Session expired".to_string()));
        }
        U::find_by_oauth2_session_id(db, cookie).await.map_err(|e| {
            tracing::info!("Cannot find user");
            Error::Unauthorized(e.to_string())
        })
    }
}

// Implement the FromRequestParts trait for the OAuthCookieUser struct
#[async_trait]
impl<S, T, U, V> FromRequestParts<S> for OAuth2CookieUser<T, U, V>
where
    S: Send + Sync,
    T: DeserializeOwned,
    U: OAuth2UserTrait<T> + ModelTrait,
    V: OAuth2SessionsTrait<U> + ModelTrait,
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
        let user =
            OAuth2CookieUser::<T, U, V>::validate_session_and_retrieve_user(&state.db, &cookie)
                .await
                .map_err(|e| {
                    tracing::info!("Cannot validate session");
                    (StatusCode::UNAUTHORIZED, e.to_string()).into_response()
                })?;
        Ok(Self {
            user,
            _marker: PhantomData,
            _marker2: PhantomData,
        })
    }
}
