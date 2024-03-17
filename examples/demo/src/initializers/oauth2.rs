use axum::{async_trait, Extension, Router as AxumRouter};
use loco_oauth2::{config::OAuth2Config, OAuth2ClientStore};
use loco_rs::prelude::*;

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
        let oauth2_config_value = settings
            .get("oauth2")
            .ok_or(Error::Message("oauth2 config not found".to_string()))?
            .clone();
        let oauth2_config: OAuth2Config = oauth2_config_value.try_into().map_err(|e| {
            tracing::error!(error = ?e, "could not convert oauth2 config");
            Error::Message("could not convert oauth2 config".to_string())
        })?;

        let oauth2_store = OAuth2ClientStore::new(oauth2_config, None).map_err(|e| {
            tracing::error!(error = ?e, "could not create oauth2 store");
            Error::Message("could not create oauth2 store".to_string())
        })?;
        Ok(router.layer(Extension(oauth2_store)))
    }
}
