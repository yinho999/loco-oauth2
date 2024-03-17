#![allow(elided_lifetimes_in_paths)]
#![allow(clippy::wildcard_imports)]

use loco_oauth2::migration;
pub use sea_orm_migration::prelude::*;

mod m20220101_000001_users;
mod m20231103_114510_notes;

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
