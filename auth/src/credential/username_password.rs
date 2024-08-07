use super::{Credential, PartialCredential};
use crate::{
    credential::{CredentialLookup, InsertableCredentialLookup},
    database::DatabaseConnection,
    error::*,
    schema::{
        credentials::{self, dsl::*},
        username_password_credentials::{self, dsl::*},
    },
    user::User,
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
    pub fn new(partial_username: String, partial_password: String) -> Self {
        Self {
            username: partial_username,
            password: partial_password,
        }
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

        if !valid_password {
            return Err(AuthError::NotFound("Incorrect username or password!".into()))
        }

        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<UsernamePassword> {
        let hashed_password = Argon2::default()
            .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))?
            .to_string();

        let timestamp = Utc::now().naive_utc();

        let credential = InsertableUsernamePassword {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            username: &self.username,
            password: &hashed_password,
            verified: false,
            disabled: false,
            last_update: &timestamp,
            last_authentication: &timestamp,
            created: &timestamp,
        };

        connection.transaction::<UsernamePassword, AuthError, _>(|connection| {
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
                .on_conflict(credentials::dsl::uid)
                .do_update()
                .set(username_password.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            Ok(credential)
        })
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
    pub disabled: bool,
    pub last_update: &'a NaiveDateTime,
    pub last_authentication: &'a NaiveDateTime,
    pub created: &'a NaiveDateTime,
}

#[derive(Queryable, AsChangeset, Selectable)]
#[diesel(table_name = username_password_credentials)]
#[diesel(check_for_backend(Pg))]
#[diesel(primary_key(cid))]
pub struct UsernamePassword {
    pub cid: Uuid,
    pub uid: Uuid,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub disabled: bool,
    pub last_update: NaiveDateTime,
    pub last_authentication: NaiveDateTime,
    pub created: NaiveDateTime,
}

impl UsernamePassword {
    pub fn get_by_username(
        connection: DatabaseConnection,
        query_username: &str,
    ) -> AuthResult<Self> {
        let credential = diesel::QueryDsl::filter(
            crate::schema::username_password_credentials::table,
            username.eq(query_username),
        )
        .select(UsernamePassword::as_select())
        .first(connection)?;

        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }
}

impl Credential for UsernamePassword {
    fn created(&self) -> &NaiveDateTime {
        &self.created
    }

    fn last_authentication(&self) -> &NaiveDateTime {
        &self.last_authentication
    }

    fn set_last_authentication(&mut self, connection: DatabaseConnection) -> AuthResult<()> {
        self.last_authentication = Utc::now().naive_utc();
        self.update(connection)
    }

    fn verified(&self) -> bool {
        self.verified
    }

    fn set_verified(
        &mut self,
        connection: DatabaseConnection,
        updated_verified: bool,
    ) -> AuthResult<()> {
        self.verified = updated_verified;
        self.update(connection)
    }

    fn disabled(&self) -> bool {
        self.disabled
    }

    fn set_disabled(
        &mut self,
        connection: DatabaseConnection,
        updated_disabled: bool,
    ) -> AuthResult<()> {
        self.disabled = updated_disabled;
        self.update(connection)
    }

    fn last_update(&self) -> &NaiveDateTime {
        &self.last_update
    }

    fn update(&self, connection: DatabaseConnection) -> AuthResult<()> {
        diesel::update(username_password_credentials.find(self.cid()))
            .set(self)
            .execute(connection)?;

        Ok(())
    }

    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()> {
        connection.transaction(|connection| {
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

    fn cid(&self) -> &Uuid {
        &self.cid
    }

    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self> {
        let credential = username_password_credentials
            .find(query_cid)
            .select(Self::as_select())
            .first(connection)
            .map_err(AuthError::from)?;

        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }

    fn uid(&self) -> &Uuid {
        &self.uid
    }

    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        let credential = diesel::QueryDsl::filter(
            crate::schema::username_password_credentials::table,
            username_password_credentials::dsl::uid.eq(query_uid),
        )
        .select(UsernamePassword::as_select())
        .first(connection)?;

        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }

    fn get_owner(&self, connection: DatabaseConnection) -> AuthResult<User> {
        User::get_by_uid(connection, &self.uid())
    }
}
