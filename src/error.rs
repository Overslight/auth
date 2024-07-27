use diesel::result::DatabaseErrorKind;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("The resource is invalid!")]
    Invalid,
    #[error("The resource is empty or incomplete!")]
    Missing,
    #[error("The resource already exists!")]
    AlreadyExists,
    #[error("The resource doesn\'t exist or couldn\'t be found!")]
    NotFound,
    #[error("An unknown database error occurred: {0}!")]
    Database(diesel::result::Error),
    #[error("Failed to calculate hash!")]
    Hash,
    #[error("Something went wrong!")]
    Unknown,
}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(_value: argon2::password_hash::Error) -> Self {
        Self::Hash
    }
}

impl From<diesel::result::Error> for AuthError {
    fn from(value: diesel::result::Error) -> Self {
        use diesel::result::{DatabaseErrorKind, Error};

        match value {
            Error::NotFound => Self::NotFound,
            Error::DatabaseError(kind, _) => match kind {
                DatabaseErrorKind::UniqueViolation => Self::AlreadyExists,
                DatabaseErrorKind::NotNullViolation => Self::Missing,
                DatabaseErrorKind::CheckViolation => Self::Invalid,
                _ => Self::Database(value),
            },
            _ => Self::Database(value),
        }
    }
}

impl Into<diesel::result::Error> for AuthError {
    fn into(self) -> diesel::result::Error {
        diesel::result::Error::DatabaseError(
            DatabaseErrorKind::Unknown,
            Box::new("test".to_string()),
        )
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;
