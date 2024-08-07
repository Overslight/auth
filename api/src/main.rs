use actix_identity::IdentityMiddleware;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, guard, web, App, HttpServer};
use api::middleware::{auth::AuthenticationMiddleware, database::DatabaseMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().unwrap();

    // Cookie secret key
    // Should be in .env file
    let secret_key = Key::generate();

    // Connects to the database
    let database_pool = api::database::create_pool();
    println!("[STATUS]: Connected to database!");

    // Starts the HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(AuthenticationMiddleware::new())
            .wrap(DatabaseMiddleware::new(database_pool.clone()))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_domain(Some("auth.server.com".into()))
                    .cookie_http_only(false)
                    .cookie_secure(false)
                    .build(),
            )
            .service(
                web::scope("/api")
                    .guard(guard::Host("auth.server.com"))
                    .service(api::routes::scope()),
            )
    })
    .bind(("127.0.0.1", 80))?
    .run()
    .await
}
