use loco_rs::model::ModelResult;
use loco_rs::prelude::*;
use sea_orm::DatabaseConnection;

/// Trait for OAuth2 user.
/// # Generic
/// * `T` - Should implement `DeserializeOwned` OAuth2 User Profile requested to OAuth2 provider, this depends on the scope set on the application.
#[async_trait]
pub trait OAuth2UserTrait<T>: Clone {
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
    async fn find_by_oauth2_session_id(db: &DatabaseConnection, cookie: &str) -> ModelResult<Self>;
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
    /// * `ModelError` -  When could not save the user into the DB
    async fn upsert_with_oauth(db: &DatabaseConnection, profile: &T) -> ModelResult<Self>;

    /// Generates a JWT token for the user.
    /// # Arguments
    /// * `secret` - JWT secret
    /// * `expiration` - JWT expiration time
    ///
    /// # Returns
    /// * `String` - JWT token
    ///
    /// # Errors
    /// * `ModelError` - When could not generate the JWT token
    fn generate_jwt(&self, secret: &str, expiration: &u64) -> ModelResult<String>;
}
