use crate::{
    error::{ApiErrorType, ApiResult},
    middleware::{
        auth::{DenyAuthenticated, RequireAuthenticated},
        database::Database,
    },
};
use actix_identity::Identity;
use actix_web::{
    web::{self, Json},
    HttpMessage, HttpRequest, HttpResponse, Responder, Scope,
};
use auth::{
    credential::{username_password::PartialUsernamePassword, Credential, PartialCredential},
    user::User,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct AuthenticationRequest {
    pub username: String,
    pub password: String,
}

#[actix_web::post("/authenticate")]
pub async fn authenticate(
    _: DenyAuthenticated,
    http: HttpRequest,
    mut connection: Database,
    request: web::Json<AuthenticationRequest>,
) -> ApiResult<impl Responder> {
    let user = web::block::<_, ApiResult<User>>(move || {
        let partial_credential =
            PartialUsernamePassword::new(request.username.clone(), request.password.clone());
        User::authenticate(&mut connection, partial_credential).map_err(ApiErrorType::from)
    })
    .await??;

    Identity::login(&http.extensions(), user.uid().to_string())?;

    Ok(HttpResponse::Ok().json(user))
}

#[derive(Deserialize)]
struct RegistrationRequest {
    pub username: String,
    pub password: String,
}

#[actix_web::post("/register")]
pub async fn register(
    _: DenyAuthenticated,
    http: HttpRequest,
    mut connection: Database,
    request: web::Json<RegistrationRequest>,
) -> ApiResult<impl Responder> {
    let user = web::block::<_, ApiResult<User>>(move || {
        let partial_credential =
            PartialUsernamePassword::new(request.username.clone(), request.password.clone());
        User::new(&mut connection, partial_credential).map_err(ApiErrorType::from)
    })
    .await??;

    Identity::login(&http.extensions(), user.uid().to_string())?;

    Ok(HttpResponse::Ok().json(user))
}

#[derive(Deserialize)]
struct AssociationRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct AssociationResponse {
    success: bool,
}

#[actix_web::post("/associate")]
pub async fn associate(
    user: RequireAuthenticated,
    mut connection: Database,
    request: Json<AssociationRequest>,
) -> ApiResult<impl Responder> {
    web::block::<_, ApiResult<()>>(move || {
        match user.credentials(&mut connection)?.username_password {
            Some(_) => Err(ApiErrorType::CredentialAssociated),
            None => {
                PartialUsernamePassword::new(request.username.clone(), request.password.clone())
                    .associate(&mut connection, user.uid())?;

                Ok(())
            }
        }
    })
    .await??;

    Ok(HttpResponse::Ok().json(AssociationResponse { success: true }))
}

#[derive(Deserialize)]
struct RemovalRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct RemovalResponse {
    pub success: bool,
}

#[actix_web::delete("/remove")]
pub async fn remove(
    user: RequireAuthenticated,
    mut connection: Database,
    request: Json<RemovalRequest>,
) -> ApiResult<impl Responder> {
    web::block::<_, ApiResult<()>>(move || {
        let partial_credential =
            PartialUsernamePassword::new(request.username.clone(), request.password.clone());
        let credential = User::authenticate(&mut connection, partial_credential)?
            .credentials(&mut connection)?
            .username_password(&mut connection)?;

        if credential.uid() != user.uid() {
            return Err(ApiErrorType::CredentialIncorrect);
        }

        credential
            .delete(&mut connection)
            .map_err(ApiErrorType::from)
    })
    .await??;

    Ok(HttpResponse::Ok().json(RemovalResponse { success: true }))
}

pub fn scope() -> Scope {
    web::scope("/username_password")
        .service(authenticate)
        .service(register)
        .service(associate)
        .service(remove)
}
