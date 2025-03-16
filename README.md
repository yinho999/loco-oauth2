# Loco OAuth2

Loco OAuth2 is a simple OAuth2 initializer for the Loco API. It is designed to be a tiny and easy-to-use library for
implementing OAuth2 in your application.

## Docs

Offical `RFC 6749` OAuth2 documentation can be found [here](https://datatracker.ietf.org/doc/html/rfc6749).\
Shuttle tutorial can be found [here](https://www.shuttle.rs/blog/2023/08/30/using-oauth-with-axum).

## What is OAuth2?

OAuth2 is a protocol that allows a user to grant a third-party website or application access to the user's protected
resources, without necessarily revealing their long-term credentials or even their identity. For this to work, the user
needs to authenticate with the third-party site and grant access to the client application.

## Grant Types

There are several grant types in OAuth2. Currently Loco OAuth2 supports the `Authorization Code Grant`. Client
Credentials
Grant, Implicit Grant and more are planned for future releases.

## Table of Contents

1. [Installation](#installation)
2. [Glossary](#glossary)
3. [Configuration (Authorization Code Grant)](#configuration-authorization-code-grant)
4. [Initialization](#initialization)
5. [Migration](#migration)
6. [Models](#models)
7. [Controllers](#controllers)

<a name="installation"></a>

## Installation

Cargo

```bash
cargo add loco-oauth2
```

Or Cargo.toml

```toml
[workspace.dependencies]
loco-oauth2 = { version = "0.3" }

[dependencies]
loco-oauth2 = { workspace = true }
```

<a name="glossary"></a>

## Glossary

|                              |                                                                                                          |
|------------------------------|----------------------------------------------------------------------------------------------------------|
| `OAuth2ClientGrantEnum`      | Enum for the different OAuth2 grants, an OAuth2 Client will belong to one of the `OAuth2ClientGrantEnum` |
| `OAuth2ClientStore`          | Abstraction implementation for managing one or more OAuth2 clients.                                      |
| `authorization_code::Client` | A client that uses the Authorization Code Grant.                                                         |

<a name="configuration-authorization-code-grant"></a>

## Configuration (Authorization Code Grant)

### Generate a private cookie secret key 

secret_key is used to encrypt the private cookie jar. It must be more than 64 bytes. If not provided, it will be
auto-generated.
Here is an example of how to generate a private cookie secret key.
```toml
# Cargo.toml
rand = "0.9.0-alpha.1"
axum-extra = { version = "0.9.3", features = ["cookie-private"]}
```
```rust
// src/main.rs
use axum_extra::extract::cookie::Key;
use rand::{Rng, thread_rng};

fn main() {
    // Generate a cryptographically random key of 64 bytes
    let mut rng = thread_rng();
    let mut random_key = [0u8; 64];
    rng.fill(&mut random_key);
    match Key::try_from(&random_key[..]) {
        Ok(key) => {
            println!("Random key: {:?}", key.master());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}
```

### OAuth2 Configuration

OAuth2 Configuration is done in the `config/*.yaml` file. The `oauth2` section is used to configure the OAuth2 clients.

This example is using Google Cloud as the OAuth2 provider. You need a Google Cloud project and create OAuth2 credentials
for `client_id` and `client_secret` using OAuth client Id option.  `redirect_url` is the server callback endpoint for
the provider which should set within `Authorised redirect URIs` section when creating OAuth2 client id.

```yaml
# config/*.yaml
# Initializers Configuration
initializers:
  oauth2:
    secret_key: {{get_env(name="OAUTH_PRIVATE_KEY", default="144, 76, 183, 1, 15, 184, 233, 174, 214, 251, 190, 186, 122, 61, 74, 84, 225, 110, 189, 115, 10, 251, 133, 128, 52, 46, 15, 66, 85, 1, 245, 73, 27, 113, 189, 15, 209, 205, 61, 100, 73, 31, 18, 58, 235, 105, 141, 36, 70, 92, 231, 151, 27, 32, 243, 117, 30, 244, 110, 89, 233, 196, 137, 130")}} # Optional, key for Private Cookie Jar, must be more than 64 bytes
    authorization_code: # Authorization code grant type
      - client_identifier: google # Identifier for the OAuth2 provider. Replace 'google' with your provider's name if different, must be unique within the oauth2 config.
        client_credentials:
          client_id: {{get_env(name="OAUTH_CLIENT_ID", default="oauth_client_id")}} # Replace with your OAuth2 client ID.
          client_secret: {{get_env(name="OAUTH_CLIENT_SECRET", default="oauth_client_secret")}} # Replace with your OAuth2 client secret.
        url_config:
          auth_url: {{get_env(name="AUTH_URL", default="https://accounts.google.com/o/oauth2/auth")}} # authorization endpoint from the provider
          token_url: {{get_env(name="TOKEN_URL", default="https://www.googleapis.com/oauth2/v3/token")}} # token endpoint from the provider for exchanging the authorization code for an access token
          redirect_url: {{get_env(name="REDIRECT_URL", default="http://localhost:5150/api/oauth2/google/callback/cookie")}} # server callback endpoint for the provider, for default jwt route use 'default="http://localhost:5150/api/oauth2/google/callback/cookie"'
          profile_url: {{get_env(name="PROFILE_URL", default="https://openidconnect.googleapis.com/v1/userinfo")}} # user profile endpoint from the provider for getting user data
          scopes:
            - {{get_env(name="SCOPES_1", default="https://www.googleapis.com/auth/userinfo.email")}} # Scopes for requesting access to user data
            - {{get_env(name="SCOPES_2", default="https://www.googleapis.com/auth/userinfo.profile")}} # Scopes for requesting access to user data
        cookie_config:
          protected_url: {{get_env(name="PROTECTED_URL", default="http://localhost:5150/api/oauth2/protected")}} # Optional for jwt - For redirecting to protect url in cookie to prevent XSS attack
        timeout_seconds: 600 # Optional, default 600 seconds
```

<a name="initialization"></a>

## Initialization

We are going to use the initializer functionality in Loco framework to initialize the OAuth2 client.

Firstly we need to create a session store for the storing the csrf token. We will use the `AxumSessionStore` for this
purpose. We will create a new initializer struct for `AxumSessionStore` and implement the `Initializer` trait.
```toml
# Cargo.toml
# axum sessions
axum_session = { version = "0.16.0" }
```
```rust 
// src/initializers/axum_session.rs
use async_trait::async_trait;
use axum::Router as AxumRouter;
use loco_rs::prelude::*;

pub struct AxumSessionInitializer;

#[async_trait]
impl Initializer for AxumSessionInitializer {
    fn name(&self) -> String {
        "axum-session".to_string()
    }

    async fn after_routes(&self, router: AxumRouter, _ctx: &AppContext) -> Result<AxumRouter> {
        // Create the session store configuration
        let session_config =
            axum_session::SessionConfig::default().with_table_name("sessions_table");
        // Create the session store
        let session_store =
            axum_session::SessionStore::<axum_session::SessionNullPool>::new(None, session_config)
                .await
                .unwrap();
        // Add the session store to the AxumRouter as an extension
        let router = router.layer(axum_session::SessionLayer::new(session_store));
        Ok(router)
    }
}
```

We will create a new initializer struct for `OAuth2ClientStore` and implement the `Initializer` trait. In
the `after_routes` function, we will get the `oauth2` settings from the `config` and create the `OAuth2ClientStore` and
add it to the `AxumRouter` as an extension.

```rust
// src/initializers/oauth2.rs
use axum::{Extension, Router as AxumRouter};
use loco_oauth2::{config::Config, OAuth2ClientStore};
use loco_rs::prelude::*;

pub struct OAuth2StoreInitializer;

#[async_trait]
impl Initializer for OAuth2StoreInitializer {
    fn name(&self) -> String {
        "oauth2-store".to_string()
    }
    async fn after_routes(&self, router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        // Get all the settings from the config
        let settings = ctx.config.initializers.clone().ok_or_else(|| {
            Error::Message("Initializers config not configured for OAuth2".to_string())
        })?;
        // Get the oauth2 config in json format
        let oauth2_config_value = settings
            .get("oauth2")
            .ok_or(Error::Message(
                "Oauth2 config not found in Initializer configuration".to_string(),
            ))?
            .clone();
        // Convert the oauth2 config json to OAuth2Config
        let oauth2_config: Config = oauth2_config_value.try_into().map_err(|e| {
            tracing::error!(error = ?e, "could not convert oauth2 config from yaml");
            Error::Message("could not convert oauth2 config from yaml".to_string())
        })?;
        // Create the OAuth2ClientStore
        let oauth2_store = OAuth2ClientStore::new(oauth2_config).map_err(|e| {
            tracing::error!(error = ?e, "could not create oauth2 store from config");
            Error::Message("could not create oauth2 store from config".to_string())
        })?;
        // Add the OAuth2ClientStore to the AxumRouter as an extension
        Ok(router.layer(Extension(oauth2_store)))
    }
}
```

Do not forget to add the initializers to the `App` struct.

```rust
// src/app.rs
pub struct App;

#[async_trait]
impl Hooks for App {
    async fn initializers(_ctx: &AppContext) -> Result<Vec<Box<dyn Initializer>>> {
        Ok(vec![
            Box::new(initializers::axum_session::AxumSessionInitializer),
            Box::new(initializers::oauth2::OAuth2StoreInitializer),
        ])
    }
}
```

<a name="migration"></a>

## Migration

### Installation

We need to install workspace `loco-oauth2` library within the migration folder.

```toml
# migration/Cargo.toml
[dependencies]
loco-oauth2 = { workspace = true }
```

### Migration Script

A migration is required to create the `o_auth2_sessions` table for the `OAuth2ClientStore`.

The `o_auth2_sessions` table is used to connect the user to the OAuth2 session, and it is used to store session data.

Instead of creating the table by hand, you can import the migration script from `loco_oauth2` into your migration
folder.

```rust
// migration/src/lib.rs
use loco_oauth2::migration;
pub use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_users::Migration),
            Box::new(m20231103_114510_notes::Migration),
            // Register OAuth2 sessions migration here
            Box::new(migration::m20240101_000000_oauth2_sessions::Migration),
        ]
    }
}
```

Here shape of the `o_auth2_sessions` table.

```postgresql
CREATE TABLE o_auth2_sessions
(
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    id         SERIAL PRIMARY KEY,
    session_id VARCHAR                             NOT NULL,
    expires_at TIMESTAMP                           NOT NULL,
    user_id    INTEGER                             NOT NULL
        CONSTRAINT "fk-sessions-users"
            REFERENCES users
            ON UPDATE CASCADE
            ON DELETE CASCADE
);
```

Run migration using the following command.

```bash
cargo loco db migrate
```

Then generate all the models using the following command.

```bash
cargo loco db entities
```

<a name="models"></a>

## Models

The user details shape returns from the OAuth2 Provider depends on the scope of your settings.
Here is an example of the user model for Google OAuth2 provider. You can change the fields based on what you requested.
For more information on scopes, see
[Google Scopes](https://developers.google.com/identity/protocols/oauth2/scopes)

```rust
// src/models/user.rs
/// `OAuth2UserProfile` user profile information via scopes
/// https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuth2UserProfile {
    // https://www.googleapis.com/auth/userinfo.email	See your primary Google Account email address
    pub email: String,
    // https://www.googleapis.com/auth/userinfo.profile   See your personal info, including any personal info you've made publicly available
    pub name: String,
    // sub field is unique
    pub sub: String,
    pub email_verified: bool,
    pub given_name: Option<String>, // Some accounts don't have this field
    pub family_name: Option<String>, // Some accounts don't have this field
    pub picture: Option<String>, // Some accounts don't have this field
    pub locale: Option<String>, // Some accounts don't have this field
}
```

Next we need to implement 2 traits for the `users::Model` model and the `o_auth2_sessions::Model`.

### `OAuth2UserTrait` Example

```rust
// src/models/users.rs
use loco_oauth2::models::users::OAuth2UserTrait;
use loco_rs::{auth::jwt, hash, prelude::*};
use super::o_auth2_sessions;
use async_trait::async_trait;
use chrono::offset::Local;

#[async_trait]
impl OAuth2UserTrait<OAuth2UserProfile> for Model {
    /// Asynchronously finds user by OAuth2 session id.
    /// # Arguments
    /// * `db` - Database connection
    /// * `cookie` - OAuth2 session id
    ///
    /// # Returns
    /// * `Self` - The `OAuth2UserTrait` struct
    ///
    /// # Errors
    /// * `ModelError` - When could not find the user in the DB
    async fn find_by_oauth2_session_id(
        db: &DatabaseConnection,
        session_id: &str,
    ) -> ModelResult<Self> {
        // find the session by the session id
        let session = o_auth2_sessions::Entity::find()
            .filter(super::_entities::o_auth2_sessions::Column::SessionId.eq(session_id))
            .one(db)
            .await?
            .ok_or_else(|| ModelError::EntityNotFound)?;
        // if the session is found, find the user by the user id
        let user = users::Entity::find()
            .filter(users::Column::Id.eq(session.user_id))
            .one(db)
            .await?;
        user.ok_or_else(|| ModelError::EntityNotFound)
    }
    /// Asynchronously upsert user with OAuth data and saves it to the
    /// database.
    /// # Arguments
    /// * `db` - Database connection
    /// * `profile` - OAuth profile
    ///
    /// # Returns
    /// * `Self` - The `OAuth2UserTrait` struct
    ///
    /// # Errors
    ///
    /// When could not save the user into the DB
    async fn upsert_with_oauth(
        db: &DatabaseConnection,
        profile: &OAuth2UserProfile,
    ) -> ModelResult<Self> {
        let txn = db.begin().await?;
        let user = match users::Entity::find()
            .filter(users::Column::Email.eq(&profile.email))
            .one(&txn)
            .await?
        {
            None => {
                // We use the sub field as the user fake password since sub is unique
                let password_hash =
                    hash::hash_password(&profile.sub).map_err(|e| ModelError::Any(e.into()))?;
                // Create the user into the database
                users::ActiveModel {
                    email: ActiveValue::set(profile.email.to_string()),
                    name: ActiveValue::set(profile.name.to_string()),
                    email_verified_at: ActiveValue::set(Some(Local::now().into())),
                    password: ActiveValue::set(password_hash),
                    ..Default::default()
                }
                    .insert(&txn)
                    .await
                    .map_err(|e| {
                        tracing::error!("Error while trying to create user: {e}");
                        ModelError::Any(e.into())
                    })?
            }
            // Do nothing if user exists
            Some(user) => user,
        };
        txn.commit().await?;
        Ok(user)
    }

    /// Generates a JWT
    /// # Arguments
    /// * `secret` - JWT secret
    /// * `expiration` - JWT expiration time
    ///
    /// # Returns
    /// * `String` - JWT token
    ///
    /// # Errors
    /// * `ModelError` - When could not generate the JWT
    fn generate_jwt(&self, secret: &str, expiration: &u64) -> ModelResult<String> {
        self.generate_jwt(secret, expiration)
    }
}

```

### `OAuth2SessionsTrait` Example

```rust
// src/models/o_auth2_sessions.rs
pub use super::_entities::o_auth2_sessions::{self, ActiveModel, Entity, Model};
use super::users;
use async_trait::async_trait;
use chrono::Local;
use loco_oauth2::{
    base_oauth2::basic::BasicTokenResponse, base_oauth2::TokenResponse,
    models::oauth2_sessions::OAuth2SessionsTrait,
};
use loco_rs::prelude::*;
use sea_orm::entity::prelude::*;

#[async_trait]
impl OAuth2SessionsTrait<users::Model> for Model {
    /// Check if a session is expired from the database
    ///
    /// # Arguments
    /// db: &`DatabaseConnection` - Database connection
    /// session_id: &str - Session id
    /// # Returns
    /// A boolean
    /// # Errors
    /// Returns a `ModelError` if the session is not found
    async fn is_expired(db: &DatabaseConnection, session_id: &str) -> ModelResult<bool> {
        let oauth2_session = o_auth2_sessions::Entity::find()
            .filter(o_auth2_sessions::Column::SessionId.eq(session_id))
            .one(db)
            .await?
            .ok_or_else(|| ModelError::EntityNotFound)?;
        Ok(oauth2_session.expires_at < Utc::now())
    }

    /// Upsert a session with OAuth
    ///
    /// # Arguments
    /// db: &`DatabaseConnection` - Database connection
    /// token: &`BasicTokenResponse` - OAuth token
    /// user: &`users::Model` - User
    /// # Returns
    /// A session
    /// # Errors
    /// Returns a `ModelError` if the session cannot be upserted
    async fn upsert_with_oauth2(
        db: &DatabaseConnection,
        token: &BasicTokenResponse,
        user: &users::Model,
    ) -> ModelResult<Self> {
        let txn = db.begin().await?;
        let oauth2_session_id = token.access_token().secret().clone();
        let oauth2_session = match o_auth2_sessions::Entity::find()
            .filter(o_auth2_sessions::Column::UserId.eq(user.id))
            .one(&txn)
            .await?
        {
            Some(oauth2_session) => {
                // Update the session
                let mut oauth2_session: o_auth2_sessions::ActiveModel = oauth2_session.into();
                oauth2_session.session_id = ActiveValue::set(oauth2_session_id);
                oauth2_session.expires_at =
                    ActiveValue::set(Utc::now() + token.expires_in().unwrap());
                oauth2_session.updated_at = ActiveValue::set(Utc::now());
                oauth2_session.update(&txn).await?
            }
            None => {
                // Create the session
                o_auth2_sessions::ActiveModel {
                    session_id: ActiveValue::set(oauth2_session_id),
                    expires_at: ActiveValue::set(
                        Utc::now() + token.expires_in().unwrap(),
                    ),
                    user_id: ActiveValue::set(user.id),
                    ..Default::default()
                }
                    .insert(&txn)
                    .await?
            }
        };
        txn.commit().await?;
        Ok(oauth2_session)
    }
}
```

<a name="controllers"></a>

## Controllers

We need to implement 3 controllers for the OAuth2 flow.

`authorization_url` - This controller is used to get the authorization URL to redirect the user to the OAuth2 provider.

`callback` - This controller is used to handle the callback from the OAuth2 provider. We can use either return a `PrivateCookieJar`(which redirects to `protected` route) or a `JWT` token.

`protected` - This controller is used to protect the route from unauthorized access.

### `OAuth2Controller` Example

```rust
// src/controllers/oauth2.rs
use axum_session::SessionNullPool;
use loco_oauth2::controllers::oauth2::get_authorization_url;
use loco_oauth2::OAuth2ClientStore;
use crate::models::{o_auth2_sessions, users, users::OAuth2UserProfile};

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
pub async fn google_authorization_url(
    session: Session<SessionNullPool>,
    Extension(oauth2_store): Extension<OAuth2ClientStore>,
) -> Result<String> {
    // Get the `google` Authorization Code Grant client from the `OAuth2ClientStore`
    let mut client = oauth2_store
        .get_authorization_code_client("google")
        .await
        .map_err(|e| {
            tracing::error!("Error getting client: {:?}", e);
            Error::InternalServerError
        })?;
    // Get the authorization URL and save the csrf token in the session
    let auth_url = get_authorization_url(session, &mut client).await;
    drop(client);
    Ok(auth_url)
}
```

### `CallbackController Cookie` Example

```rust
use axum_session::SessionNullPool;
use loco_oauth2::controllers::oauth2::callback;
use loco_oauth2::OAuth2ClientStore;
use crate::models::{o_auth2_sessions, users, users::OAuth2UserProfile};

// src/controllers/oauth2.rs
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
/// URL
/// # Errors
/// * `loco_rs::errors::Error`
pub async fn google_callback_cookie(
    State(ctx): State<AppContext>,
    session: Session<SessionNullPool>,
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
    // This function will validate the state from the callback. Then it will exchange the code for a token and then get the user profile. After that, the function will upsert the user and the session and set the token in a short live cookie and save the cookie in the private cookie jar. Lastly, the function will create a response with the short live cookie and the redirect to the protected URL
    let response = callback::<OAuth2UserProfile, users::Model, o_auth2_sessions::Model, SessionNullPool, >(ctx, session, params, jar, &mut client).await?;
    drop(client);
    Ok(response)
}
```

### `CallbackController JWT` Example - SPA applications
```rust
/// The callback URL for the `OAuth2` flow
/// This will exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie Lastly, it will redirect the user to the protected URL
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
pub async fn google_callback_jwt(
    State(ctx): State<AppContext>,
    session: Session<SessionNullPool>,
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
    // Get JWT secret from the config
    let jwt_secret = ctx.config.get_jwt_config()?;
    let user = callback_jwt::<OAuth2UserProfile, users::Model, o_auth2_sessions::Model, SessionNullPool>(&ctx, session, params, &mut client).await?;
    drop(client);
    let token = user
        .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;
    // Return jwt token
    Ok(token)
}
```

`ProtectedController` Example

```rust
// src/controllers/oauth2.rs
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
```

### Google boilerplate Example - Cookie

Since we are using Google OAuth2 provider, there is a google boilerplate code to get the authorization URL and the
callback cookie.

```rust
// src/controllers/oauth2.rs
use axum_session::SessionNullPool;
use loco_oauth2::controllers::{
    middleware::OAuth2CookieUser,
    oauth2::{google_authorization_url, google_callback_cookie},
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
        .add("/protected", get(protected))
}
```

### Google boilerplate Example - JWT

Since we are using Google OAuth2 provider, there is a google boilerplate code to get the authorization URL and the callback jwt.

```rust
// src/controllers/oauth2.rs
use axum_session::SessionNullPool;
use loco_oauth2::controllers::{
    oauth2::{google_authorization_url, google_callback_jwt},
};
use loco_rs::prelude::*;

use crate::{
    models::{o_auth2_sessions, users, users::OAuth2UserProfile},
    views::auth::LoginResponse,
};


pub fn routes() -> Routes {
    Routes::new()
        .prefix("api/oauth2")
        .add("/google", get(google_authorization_url::<SessionNullPool>))
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
}
```