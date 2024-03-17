use crate::OAuth2ClientStore;
use async_trait::async_trait;
use axum::response::{IntoResponse, IntoResponseParts, ResponseParts};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::Response,
    Extension, RequestPartsExt,
};
use axum_extra::extract;
use axum_extra::extract::PrivateCookieJar;
use cookie::{Cookie, Key};
use http::HeaderMap;
use loco_rs::prelude::AppContext;
use std::convert::Infallible;

pub struct OAuth2PrivateCookieJar(extract::cookie::PrivateCookieJar);

impl IntoResponse for OAuth2PrivateCookieJar {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

impl IntoResponseParts for OAuth2PrivateCookieJar {
    type Error = Infallible;
    fn into_response_parts(self, res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        self.0.into_response_parts(res)
    }
}

impl AsMut<extract::cookie::PrivateCookieJar> for OAuth2PrivateCookieJar {
    fn as_mut(&mut self) -> &mut extract::cookie::PrivateCookieJar {
        &mut self.0
    }
}

impl OAuth2PrivateCookieJar {
    pub fn add<C: Into<Cookie<'static>>>(mut self, cookie: C) -> Self {
        Self(self.0.add(cookie.into()))
    }
    pub fn from_headers(headers: &HeaderMap, key: Key) -> Self {
        Self(extract::cookie::PrivateCookieJar::from_headers(
            headers, key,
        ))
    }
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        self.0.get(name)
    }
    pub fn remove<C: Into<Cookie<'static>>>(mut self, cookie: C) -> Self {
        Self(self.0.remove(cookie.into()))
    }
    pub fn iter(&self) -> impl Iterator<Item = Cookie<'static>> + '_ {
        self.0.iter()
    }

    pub fn decrypt(&self, cookie: Cookie<'static>) -> Option<Cookie<'static>> {
        self.0.decrypt(cookie)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for OAuth2PrivateCookieJar
where
    S: Send + Sync,
    AppContext: FromRef<S>,
{
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> core::result::Result<Self, Self::Rejection> {
        let Extension(store) = parts
            .extract::<Extension<OAuth2ClientStore>>()
            .await
            .map_err(|err| err.into_response())?;
        let key = store.key.clone();
        let jar = extract::cookie::PrivateCookieJar::from_headers(&parts.headers, key);
        Ok(Self(jar))
    }
}
