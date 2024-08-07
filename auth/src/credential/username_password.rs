use super::{Credential, PartialCredential};
use crate::{
    credential::{CredentialLookup, InsertableCredentialLookup},
    database::DatabaseConnection,
    error::*,
    schema::{
        credentials::{self, username_password, uid},
        username_password_credentials,
    }, user::User,
};
use chrono::{NaiveDateTime, Utc};
use diesel::{pg::Pg, prelude::*};
use uuid::Uuid;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};

pub struct PartialUsernamePassword {
    pub username: String,
    pub password: String,
}

impl PartialUsernamePassword {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

impl PartialCredential<UsernamePassword> for PartialUsernamePassword {
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<UsernamePassword> {
        let credential = UsernamePassword::get_by_username(connection, &self.username)?;
        let valid_password = Argon2::default()
            .verify_password(
                self.password.as_bytes(),
                &PasswordHash::new(&credential.password)?,
            )
            .is_ok();

        if valid_password {
            Ok(credential)
        } else {
            Err(AuthError::NotFound("Incorrect username or password!".into()))
        }
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<UsernamePassword> {
        let hashed_password = Argon2::default()
            .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))?
            .to_string();

        let credential = InsertableUsernamePassword {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            username: &self.username,
            password: &hashed_password,
            verified: false,
            last_update: &Utc::now().naive_utc(),
            last_authentication: &Utc::now().naive_utc(),
            created: &Utc::now().naive_utc(),
        };

        Ok(connection.transaction(|connection| {
            let credential = diesel::insert_into(username_password_credentials::table)
                .values(&credential)
                .returning(UsernamePassword::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: None,
                github_oauth: None,
                username_password: Some(credential.cid()),
            };

            diesel::insert_into(credentials::table)
                .values(&credential_lookup)
                .on_conflict(uid)
                .do_update()
                .set(username_password.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            diesel::result::QueryResult::Ok(credential)
        })?)
    }
}

#[derive(Insertable)]
#[diesel(table_name = username_password_credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableUsernamePassword<'a> {
    pub cid: &'a Uuid,
    pub uid: &'a Uuid,
    pub username: &'a str,
    pub password: &'a str,
    pub verified: bool,
    pub last_update: &'a NaiveDateTime,
    pub last_authentication: &'a NaiveDateTime,
    pub created: &'a NaiveDateTime,
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = username_password_credentials)]
#[diesel(check_for_backend(Pg))]
pub struct UsernamePassword {
    pub cid: Uuid,
    pub uid: Uuid,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub last_update: NaiveDateTime,
    pub last_authentication: NaiveDateTime,
    pub created: NaiveDateTime,
}

impl UsernamePassword {
    pub fn get_by_username(connection: DatabaseConnection, query_username: &str) -> AuthResult<Self> {
        use crate::schema::username_password_credentials::dsl::*;

        Ok(diesel::QueryDsl::filter(
            crate::schema::username_password_credentials::table,
            username.eq(query_username),
        )
        .select(UsernamePassword::as_select())
        .first(connection)?)
    }
}

impl Credential for UsernamePassword {
    fn last_authentication(&self) -> &NaiveDateTime {
        &self.last_authentication
    }

    fn created(&self) -> &NaiveDateTime {
        &self.created
    }

    fn cid(&self) -> &Uuid {
        &self.cid
    }

    fn uid(&self) -> &Uuid {
        &self.uid
    }

    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self> {
        use crate::schema::username_password_credentials::dsl::*;

        Ok(username_password_credentials
            .find(query_cid)
            .select(UsernamePassword::as_select())
            .first(connection)?)
    }

    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        use crate::schema::username_password_credentials::dsl::*;

        Ok(diesel::QueryDsl::filter(
            crate::schema::username_password_credentials::table,
            uid.eq(query_uid),
        )
        .select(UsernamePassword::as_select())
        .first(connection)?)
    }

    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()> {
        connection.transaction(|connection| {
            use crate::schema::{credentials::dsl::*, username_password_credentials::dsl::*};

            if !CredentialLookup::get_by_uid(connection, self.uid())?.has_multiple_credentials() {
                return Err(AuthError::CredentialCannotDelete);
            }

            diesel::delete(username_password_credentials.find(self.cid())).execute(connection)?;

            diesel::update(credentials.filter(username_password.eq(self.cid())))
                .set(username_password.eq(None::<Uuid>))
                .execute(connection)?;

            Ok(())
        })
    }

    fn get_owner(&self, connection: DatabaseConnection) -> AuthResult<User> {
        User::get_by_uid(connection, &self.uid())
    }
}
