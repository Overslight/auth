use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

#[derive(Serialize, Error, Debug, Clone)]
pub enum ApiErrorType {
    #[error("The credentials are incorrect!")]
    IncorrectCredential,
    #[error("Failed to connect to auth provider!")]
    IncorrectOauthCode,
    #[error("The user doesn\'t exist or couldn\'t be found!")]
    UserNotFound,
    #[error("The user is disabled!")]
    UserDisabled,
    #[error("The user is already registered!")]
    UserExists,
    #[error("The user is already authenticated!")]
    UserAuthenticated,
    #[error("The authentication method is already associated!")]
    CredentialAssociated,
    #[error("Cannot remove the only associated authentication method!")]
    CredentialCannotRemove,
    #[error("The resource couldn\'t be found ot doesn\'t exist!")]
    ResourceNotFound,
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
}

#[derive(Serialize, Clone, Copy)]
pub enum ApiErrorCode {
    #[serde(rename = "AUTH/INCORRECT_CREDENTIAL")]
    IncorrectCredential,
    #[serde(rename = "AUTH/INCORRECT_OAUTH_CODE")]
    IncorrectOauthCode,
    #[serde(rename = "AUTH/USER_NOT_FOUND")]
    UserNotFound,
    #[serde(rename = "AUTH/USER_DISABLED")]
    UserDisabled,
    #[serde(rename = "AUTH/USER_EXISTS")]
    UserExists,
    #[serde(rename = "AUTH/USER_AUTHENTICATED")]
    UserAuthenticated,
    #[serde(rename = "AUTH/CREDENTIAL_ASSOCIATED")]
    CredentialAssociated,
    #[serde(rename = "AUTH/CREDENTIAL_CANNOT_REMOVE")]
    CredentialCannotRemove,
    #[serde(rename = "AUTH/RESOURCE_NOUT_FOUND")]
    ResourceNotFound,
    #[serde(rename = "AUTH/UNKNOWN")]
    Unknown,
}

#[derive(Serialize)]
struct ApiErrorResponse {
    pub code: ApiErrorCode,
    pub message: ApiErrorType,
}

pub type ApiResult<T> = std::result::Result<T, ApiErrorType>;

impl From<&ApiErrorType> for ApiErrorCode {
    fn from(value: &ApiErrorType) -> Self {
        match value {
            ApiErrorType::IncorrectCredential => Self::IncorrectCredential,
            ApiErrorType::IncorrectOauthCode => Self::IncorrectOauthCode,
            ApiErrorType::UserNotFound => Self::UserNotFound,
            ApiErrorType::UserDisabled => Self::UserDisabled,
            ApiErrorType::UserExists => Self::UserExists,
            ApiErrorType::UserAuthenticated => Self::UserAuthenticated,
            ApiErrorType::CredentialAssociated => Self::CredentialAssociated,
            ApiErrorType::CredentialCannotRemove => Self::CredentialCannotRemove,
            ApiErrorType::Unknown(_) => Self::Unknown,
            ApiErrorType::ResourceNotFound => Self::ResourceNotFound,
        }
    }
}

impl From<&ApiErrorType> for ApiErrorResponse {
    fn from(value: &ApiErrorType) -> Self {
        Self {
            code: value.into(),
            message: value.clone(),
        }
    }
}

impl ResponseError for ApiErrorType {
    fn status_code(&self) -> reqwest::StatusCode {
        use reqwest::StatusCode;

        match self {
            Self::IncorrectCredential | Self::IncorrectOauthCode => StatusCode::UNAUTHORIZED,
            Self::UserNotFound => StatusCode::NOT_FOUND,
            Self::UserExists | Self::CredentialAssociated | Self::CredentialCannotRemove => {
                StatusCode::CONFLICT
            }
            Self::Unknown(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserDisabled | Self::UserAuthenticated => StatusCode::FORBIDDEN,
            Self::ResourceNotFound => StatusCode::NOT_FOUND,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code()).json(ApiErrorResponse::from(self))
    }
}

impl From<auth::error::AuthError> for ApiErrorType {
    fn from(value: auth::error::AuthError) -> Self {
        use auth::error::AuthError;

        match value {
            AuthError::NotFound(_) => Self::UserNotFound,
            AuthError::Exists(_) => Self::UserExists,
            AuthError::Invalid(_) => Self::Unknown("Invalid?".into()),
            AuthError::CredentialCannotDelete => Self::CredentialCannotRemove,
            AuthError::Database(_) | AuthError::Hash | AuthError::Unknown(_) => {
                Self::Unknown("Something went wrong!".into())
            }
        }
    }
}

impl From<oauth2::url::ParseError> for ApiErrorType {
    fn from(_value: oauth2::url::ParseError) -> Self {
        Self::Unknown("The URL is incorrect or invalid!".into())
    }
}

impl From<r2d2::Error> for ApiErrorType {
    fn from(_value: r2d2::Error) -> Self {
        Self::Unknown("Something went wrong!".into())
    }
}

impl From<actix_web::error::BlockingError> for ApiErrorType {
    fn from(_value: actix_web::error::BlockingError) -> Self {
        Self::Unknown("Something went wrong!".into())
    }
}

impl From<actix_identity::error::LoginError> for ApiErrorType {
    fn from(_value: actix_identity::error::LoginError) -> Self {
        Self::Unknown("Failed to authenticate!".into())
    }
}

impl From<actix_identity::error::GetIdentityError> for ApiErrorType {
    fn from(_value: actix_identity::error::GetIdentityError) -> Self {
        Self::Unknown("Something went wrong!".into())
    }
}

impl From<uuid::Error> for ApiErrorType {
    fn from(_value: uuid::Error) -> Self {
        Self::UserNotFound
    }
}
