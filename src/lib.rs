use diesel::{Connection, PgConnection};
use dotenvy::dotenv;

pub mod credential;
pub mod database;
pub mod error;
pub mod schema;
pub mod user;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url =
        std::env::var("DATABASE_URL").expect("Missing DATABASE_URL environment variable!");

    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error: Failed to connect to {}", database_url))
}
