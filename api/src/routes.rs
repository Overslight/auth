use actix_web::{web, Scope};

pub mod email_password;
pub mod oauth;
pub mod username_password;

pub fn scope() -> Scope {
    web::scope("")
        .service(email_password::scope())
        .service(username_password::scope())
        .service(oauth::github::scope())
}
