use diesel::{
    r2d2::{ConnectionManager, Pool},
    PgConnection,
};
use r2d2::PooledConnection;

pub type DatabasePool = Pool<ConnectionManager<PgConnection>>;
pub type DatabaseConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn create_pool() -> DatabasePool {
    let database_url = std::env::var("DATABASE_URL")
        .expect("[ERROR] DATABASE_URL environment variable must be set!");
    let database_manager = ConnectionManager::<PgConnection>::new(database_url.clone());
    Pool::builder()
        .build(database_manager)
        .expect("DATABASE_URL must be a valid connection string!")
}
