use loco_rs::prelude::*;
use axum::{async_trait, Router as AxumRouter};
use loco_oauth2::config::OAuth2Config;

pub struct OAuth2StoreInitializer;

#[async_trait]
impl Initializer for OAuth2StoreInitializer {
    fn name(&self) -> String {
        "oauth2-store".to_string()
    }
    async fn after_routes(&self, router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        let settings = ctx
            .config
            .settings
            .clone()
            .ok_or_else(|| Error::Message("settings config not configured".to_string()))?;
        let oauth2_config:OAuth2Config = settings.get("oauth2").ok_or(Error::Message("oauth2 config not found".to_string()))?.clone().try_into()?;
        let oauth2_store = OAuth2Store::new(oauth2_config);
        Ok(router)
    }
}