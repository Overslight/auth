use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Exists(String),
    #[error("{0}")]
    NotFound(String),
    #[error("Failed to verify password!")]
    Hash,
    #[error("Cannot delete the only associated credential!")]
    CredentialCannotDelete,
    #[error("An unknown database error occurred: {0}")]
    Database(diesel::result::Error),
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(_value: argon2::password_hash::Error) -> Self {
        Self::Hash
    }
}

impl From<diesel::result::Error> for AuthError {
    fn from(value: diesel::result::Error) -> Self {
        use diesel::result::{DatabaseErrorKind, Error};

        match &value {
            Error::NotFound => {
                Self::NotFound("The resource couldn\'t be found or doesn\'t exist!".into())
            }
            Error::DatabaseError(kind, info) => match kind {
                DatabaseErrorKind::UniqueViolation => Self::Exists(info.message().to_owned()),
                DatabaseErrorKind::NotNullViolation | DatabaseErrorKind::CheckViolation => {
                    Self::Invalid(info.message().to_owned())
                }
                _ => Self::Database(value),
            },
            _ => Self::Database(value),
        }
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;
