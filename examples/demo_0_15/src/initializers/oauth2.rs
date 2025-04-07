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
