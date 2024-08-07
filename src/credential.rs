use crate::schema::credentials;
use crate::user::User;
use crate::{database::DatabaseConnection, error::*};
use chrono::NaiveDateTime;
use diesel::pg::Pg;
use diesel::prelude::*;
use email_password::EmailPassword;
use github::GithubOauth;
use serde::{Deserialize, Serialize};
use username_password::UsernamePassword;
use uuid::Uuid;

pub mod email_password;
pub mod github;
pub mod username_password;

#[derive(Serialize, Deserialize, Debug)]
pub enum OauthProviders {
    #[serde(rename = "github")]
    GithubOauth,
}

pub trait Credential
where
    Self: Sized,
{
    fn created(&self) -> &NaiveDateTime;

    fn last_authentication(&self) -> &NaiveDateTime;
    fn set_last_authentication(&mut self, connection: DatabaseConnection) -> AuthResult<()>;

    fn verified(&self) -> bool;
    fn set_verified(
        &mut self,
        connection: DatabaseConnection,
        updated_verified: bool,
    ) -> AuthResult<()>;

    fn disabled(&self) -> bool;
    fn set_disabled(
        &mut self,
        connection: DatabaseConnection,
        updated_disabled: bool,
    ) -> AuthResult<()>;

    fn last_update(&self) -> &NaiveDateTime;
    fn update(&self, connection: DatabaseConnection) -> AuthResult<()>;
    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()>;

    fn cid(&self) -> &Uuid;
    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self>;

    fn uid(&self) -> &Uuid;
    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self>;

    fn get_owner(&self, connection: DatabaseConnection) -> AuthResult<User>;
}

pub trait PartialCredential<T>
where
    T: Credential,
{
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<T>;
    fn associate(&self, connection: DatabaseConnection, owner_uid: &Uuid) -> AuthResult<T>;
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(Pg))]
pub struct CredentialLookup {
    pub uid: Uuid,
    pub email_password: Option<Uuid>,
    pub github_oauth: Option<Uuid>,
    pub username_password: Option<Uuid>,
}

impl CredentialLookup {
    pub fn uid(&self) -> &Uuid {
        &self.uid
    }

    pub fn has_multiple_credentials(&self) -> bool {
        (self.email_password.is_some() as u32)
            + (self.github_oauth.is_some() as u32)
            + (self.username_password.is_some() as u32)
            > 1
    }

    pub fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        credentials::table
            .find(query_uid)
            .select(Self::as_select())
            .first(connection)
            .map_err(AuthError::from)
    }

    pub fn email_password(&self, connection: DatabaseConnection) -> AuthResult<EmailPassword> {
        match self.email_password {
            Some(cid) => EmailPassword::get_by_cid(connection, &cid),
            None => Err(AuthError::NotFound(
                "No email/password credential is associated!".into(),
            )),
        }
    }

    pub fn github_oauth(&self, connection: DatabaseConnection) -> AuthResult<GithubOauth> {
        match self.github_oauth {
            Some(cid) => GithubOauth::get_by_cid(connection, &cid),
            None => Err(AuthError::NotFound(
                "No GitHub account is associated!".into(),
            )),
        }
    }

    pub fn username_password(
        &self,
        connection: DatabaseConnection,
    ) -> AuthResult<UsernamePassword> {
        match self.username_password {
            Some(cid) => UsernamePassword::get_by_cid(connection, &cid),
            None => Err(AuthError::NotFound(
                "No username/password credential is associated!".into(),
            )),
        }
    }
}

#[derive(Insertable, Debug)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableCredentialLookup<'a> {
    pub uid: &'a Uuid,
    pub email_password: Option<&'a Uuid>,
    pub github_oauth: Option<&'a Uuid>,
    pub username_password: Option<&'a Uuid>,
}
