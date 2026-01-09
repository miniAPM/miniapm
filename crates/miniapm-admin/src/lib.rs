pub mod web;

use axum::Router;
use miniapm::DbPool;

pub fn routes(pool: DbPool) -> Router<DbPool> {
    web::routes(pool.clone())
}

pub fn auth_routes() -> Router<DbPool> {
    web::auth_routes()
}
