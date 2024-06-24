use axum_session::SessionNullPool;
use loco_oauth2::controllers::{
    middleware::OAuth2CookieUser,
    oauth2::{google_authorization_url, google_callback_cookie, google_callback_jwt},
};
use loco_rs::prelude::*;

use crate::{
    models::{o_auth2_sessions, users, users::OAuth2UserProfile},
    views::auth::LoginResponse,
};

async fn protected(
    State(ctx): State<AppContext>,
    // Extract the user from the Cookie via middleware
    user: OAuth2CookieUser<OAuth2UserProfile, users::Model, o_auth2_sessions::Model>,
) -> Result<Response> {
    let user: &users::Model = user.as_ref();
    let jwt_secret = ctx.config.get_jwt_config()?;
    // Generate a JWT token
    let token = user
        .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;
    // Return the user and the token in JSON format
    format::json(LoginResponse::new(user, &token))
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("api/oauth2")
        .add("/google", get(google_authorization_url::<SessionNullPool>))
        // Route for the Cookie callback
        .add(
            "/google/callback/cookie",
            get(google_callback_cookie::<
                OAuth2UserProfile,
                users::Model,
                o_auth2_sessions::Model,
                SessionNullPool,
            >),
        )
        // Route for the JWT callback
        .add(
            "/google/callback/jwt",
            get(google_callback_jwt::<
                OAuth2UserProfile,
                users::Model,
                o_auth2_sessions::Model,
                SessionNullPool,
            >),
        )
        .add("/protected", get(protected))
}
