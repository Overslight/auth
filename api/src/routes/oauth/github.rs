use std::str::FromStr;

use actix_identity::Identity;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder, Scope};
use auth::{
    credential::{github::PartialGithubOauth, Credential, PartialCredential},
    user::User,
};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::Url;
use serde::Deserialize;

use crate::{
    error::{ApiErrorType, ApiResult},
    middleware::{auth::AllowAuthenticated, database::Database}, routes::oauth::{OauthCallbackAction, OauthCallbackRequest},
};

const USER_AGENT: &str = "Underslight Auth";
const GITHUB_USER_API_ENDPOINT: &str = "https://api.github.com/user";
const GITHUB_AUTH_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";

pub(super) fn client() -> BasicClient {
    BasicClient::new(
        ClientId::new(
            std::env::var("GITHUB_CLIENT_ID")
                .expect("GITHUB_CLIENT_ID environment variable must be set!"),
        ),
        Some(ClientSecret::new(
            std::env::var("GITHUB_CLIENT_SECRET")
                .expect("GITHUB_CLIENT_SECRET environment variable must be set!"),
        )),
        AuthUrl::new(GITHUB_AUTH_ENDPOINT.to_string())
            .expect("Invalid github authorization endpoint!"),
        Some(
            TokenUrl::new(GITHUB_TOKEN_ENDPOINT.to_string())
                .expect("Invalid github token endpoint!"),
        ),
    )
}

#[actix_web::route("/{action}", method = "GET", method = "POST")]
pub async fn action(action: web::Path<String>) -> ApiResult<impl Responder> {
    match OauthCallbackAction::from_str(action.into_inner().as_str()) {
        Ok(action) => {
            let (authorization_url, _csrf_state) = client()
                .set_redirect_uri(RedirectUrl::from_url(Url::parse(
                    format!(
                        "http://auth.server.com/api/github/callback?action={}",
                        action
                    )
                    .as_str(),
                )?))
                .authorize_url(CsrfToken::new_random)
                .add_scope(oauth2::Scope::new("user".to_string()))
                .url();

            Ok(HttpResponse::Found()
                .insert_header(("Location", authorization_url.to_string()))
                .finish())
        }
        Err(_) => Err(ApiErrorType::ResourceNotFound),
    }
}

#[actix_web::get("/callback")]
pub async fn callback(
    user: AllowAuthenticated,
    mut connection: Database,
    query: web::Query<OauthCallbackRequest>,
    request: HttpRequest,
) -> ApiResult<impl Responder> {
    if user.is_some() && !query.action.requires_authentication() {
        return Err(ApiErrorType::UserAuthenticated);
    } else if user.is_none() && query.action.requires_authentication() {
        return Err(ApiErrorType::IncorrectCredential);
    }

    // Creates the GitHub Oauth2 client
    let client = client();

    let access_token = client
        .exchange_code(query.code.clone())
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|_| ApiErrorType::IncorrectOauthCode)?;

    let user_data = reqwest::Client::new()
        .get(GITHUB_USER_API_ENDPOINT)
        .header("User-Agent", USER_AGENT)
        .header(
            "Authorization",
            format!("Bearer {}", access_token.access_token().secret()),
        )
        .send()
        .await
        .map_err(|_| ApiErrorType::Unknown("Failed to connect to GitHub!".into()))?
        .text()
        .await
        .map_err(|_| ApiErrorType::Unknown("Failed to connect to GitHub!".into()))?;

    #[derive(Deserialize)]
    struct GithubUserData {
        login: String,
        id: i32,
    }

    let user_data = serde_json::from_str::<GithubUserData>(&user_data)
        .map_err(|_| ApiErrorType::Unknown("Failed to connect to GitHub!".into()))?;

    let partial_credential = PartialGithubOauth::new(user_data.id, user_data.login);
    let extensions = &request.extensions();

    match query.action {
        OauthCallbackAction::Authenticate => {
            let user = web::block::<_, ApiResult<User>>(move || {
                User::new(&mut connection, partial_credential).map_err(ApiErrorType::from)
            })
            .await??;
            Identity::login(extensions, user.uid().to_string())?;
            Ok(HttpResponse::Ok().json(user))
        }
        OauthCallbackAction::Register => {
            let user = web::block::<_, ApiResult<User>>(move || {
                User::authenticate(&mut connection, partial_credential).map_err(ApiErrorType::from)
            })
            .await??;
            Identity::login(extensions, user.uid().to_string())?;
            Ok(HttpResponse::Ok().json(user))
        }
        OauthCallbackAction::Associate => {
            if let Some(user) = user.0 {
                web::block::<_, ApiResult<()>>(move || {
                    partial_credential.associate(&mut connection, user.uid())?;
                    Ok(())
                })
                .await??;
                Ok(HttpResponse::Ok().finish())
            } else {
                Err(ApiErrorType::IncorrectCredential)
            }
        }
        OauthCallbackAction::Remove => {
            if let Some(user) = user.0 {
                web::block::<_, ApiResult<()>>(move || {
                    let credential = User::authenticate(&mut connection, partial_credential)?
                        .credentials(&mut connection)?
                        .github_oauth(&mut connection)?;

                    if credential.uid() != user.uid() {
                        return Err(ApiErrorType::IncorrectCredential);
                    }

                    credential.delete(&mut connection)?;

                    Ok(())
                })
                .await??;

                Ok(HttpResponse::Ok().finish())
            } else {
                Err(ApiErrorType::IncorrectCredential)
            }
        }
    }
}

pub fn scope() -> Scope {
    web::scope("/github").service(callback).service(action)
}
