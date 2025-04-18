use axum::debug_handler;
use loco_rs::prelude::*;

use crate::models::_entities::users;
use crate::views::auth::CurrentResponse;

#[debug_handler]
async fn current(auth: auth::JWT, State(ctx): State<AppContext>) -> Result<Response> {
    let user = users::Model::find_by_pid(&ctx.db, &auth.claims.pid).await?;
    format::json(CurrentResponse::new(&user))
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("api/user")
        .add("/current", get(current))
}
