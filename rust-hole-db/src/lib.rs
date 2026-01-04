pub mod models;

use sea_orm::{Database, DatabaseConnection};
use std::sync::Arc;
use sea_orm::EntityTrait; 
use tokio::sync::OnceCell;

use crate::models::blocked_domains::Entity as BlockedDomainEntity;
use crate::models::blocked_domains::Model as BlockedDomainModel;

static DB_CONN: OnceCell<Arc<DatabaseConnection>> = OnceCell::const_new();

pub async fn init_db() -> anyhow::Result<()> {
    let conn = Database::connect("sqlite://rust-hole-db/rusthole.db").await?;
    DB_CONN.set(Arc::new(conn))
        .map_err(|_| anyhow::anyhow!("Database already initialized"))?;
    Ok(())
}

pub fn get_db() -> Arc<DatabaseConnection> {
    DB_CONN.get().expect("Database not initialized. Call init_db() first.").clone()
}

pub async fn get_all_blocked_domains() -> Result<Vec<BlockedDomainModel>, sea_orm::DbErr> {
    let db = get_db();
    let domains = BlockedDomainEntity::find().all(&*db).await?;
    Ok(domains)
}
