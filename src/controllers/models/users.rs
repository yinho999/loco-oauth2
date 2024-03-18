use loco_rs::model::ModelResult;
use loco_rs::prelude::*;
use sea_orm::DatabaseConnection;
#[async_trait]
pub trait OAuth2UserTrait<T>: Clone {
    async fn find_by_oauth2_session_id(db: &DatabaseConnection, cookie: &str) -> ModelResult<Self>;
    /// Asynchronously creates user with OAuth data and saves it to the
    /// database.
    ///
    /// # Errors
    ///
    /// When could not save the user into the DB
    async fn upsert_with_oauth(db: &DatabaseConnection, profile: &T) -> ModelResult<Self>;
}
