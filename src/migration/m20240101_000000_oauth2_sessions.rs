use sea_orm_migration::{
    prelude::*,
    schema::{integer, pk_auto, string, table_auto, timestamp},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                table_auto(OAuth2Sessions::Table)
                    .col(pk_auto(OAuth2Sessions::Id))
                    .col(string(OAuth2Sessions::SessionId))
                    .col(timestamp(OAuth2Sessions::ExpiresAt))
                    .col(integer(OAuth2Sessions::UserId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-sessions-users")
                            .from(OAuth2Sessions::Table, OAuth2Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OAuth2Sessions::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum OAuth2Sessions {
    Table,
    Id,
    SessionId,
    ExpiresAt,
    UserId,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
