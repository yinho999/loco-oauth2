#![allow(elided_lifetimes_in_paths)]
#![allow(clippy::wildcard_imports)]
pub use sea_orm_migration::prelude::*;
use loco_oauth2::migration;
mod m20220101_000001_users;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_users::Migration),
            Box::new(migration::m20240101_000000_oauth2_sessions::Migration),
            // inject-above (do not remove this comment)
        ]
    }
}
