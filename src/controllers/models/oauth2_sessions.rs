use loco_rs::model::ModelResult;
use loco_rs::prelude::*;
use oauth2::basic::BasicTokenResponse;
use sea_orm::DatabaseConnection;

#[async_trait]
pub trait OAuth2SessionsTrait<T>: Clone {
    /// Check if a session is expired from the database
    ///
    /// # Arguments
    /// db: &`DatabaseConnection` - Database connection
    /// session_id: &str - Session id
    /// # Returns
    /// A boolean
    /// # Errors
    /// Returns a `ModelError` if the session is not found
    async fn is_expired(db: &DatabaseConnection, cookie: &str) -> ModelResult<bool>;
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
        user: &T,
    ) -> ModelResult<Self>;
}
