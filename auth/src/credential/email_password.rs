use super::{Credential, PartialCredential};
use crate::{
    credential::{CredentialLookup, InsertableCredentialLookup},
    database::DatabaseConnection,
    error::*,
    schema::{
        credentials::{self, dsl::*},
        email_password_credentials::{self, dsl::*},
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

pub struct PartialEmailPassword {
    pub email: String,
    pub password: String,
}

impl PartialEmailPassword {
    pub fn new(partial_email: String, partial_password: String) -> Self {
        Self {
            email: partial_email,
            password: partial_password,
        }
    }
}

impl PartialCredential<EmailPassword> for PartialEmailPassword {
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<EmailPassword> {
        let mut credential = EmailPassword::get_by_email(connection, &self.email)?;

        // Checks if the password is correct
        let valid_password = Argon2::default()
            .verify_password(
                self.password.as_bytes(),
                &PasswordHash::new(&credential.password)?,
            )
            .is_ok();

        if !valid_password {
            return Err(AuthError::NotFound("Incorrect email or password!".into()));
        }

        credential.set_last_authentication(connection)?;

        Ok(credential)
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<EmailPassword> {
        let hashed_password = Argon2::default()
            .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))?
            .to_string();

        let timestamp = Utc::now().naive_utc();

        let credential = InsertableEmailPassword {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            email: &self.email,
            password: &hashed_password,
            verified: false,
            last_update: &timestamp,
            last_authentication: &timestamp,
            created: &timestamp,
            disabled: false,
        };

        connection.transaction::<EmailPassword, AuthError, _>(|connection| {
            let credential = diesel::insert_into(email_password_credentials::table)
                .values(&credential)
                .returning(EmailPassword::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: Some(credential.cid()),
                github_oauth: None,
                username_password: None,
            };

            diesel::insert_into(credentials::table)
                .values(&credential_lookup)
                .on_conflict(credentials::dsl::uid)
                .do_update()
                .set(email_password.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            Ok(credential)
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = email_password_credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableEmailPassword<'a> {
    pub cid: &'a Uuid,
    pub uid: &'a Uuid,
    pub email: &'a str,
    pub password: &'a str,
    pub verified: bool,
    pub last_update: &'a NaiveDateTime,
    pub last_authentication: &'a NaiveDateTime,
    pub created: &'a NaiveDateTime,
    pub disabled: bool,
}

#[derive(Queryable, AsChangeset, Selectable, Debug)]
#[diesel(table_name = email_password_credentials)]
#[diesel(check_for_backend(Pg))]
#[diesel(primary_key(cid))]
pub struct EmailPassword {
    pub cid: Uuid,
    pub uid: Uuid,
    pub email: String,
    pub password: String,
    pub verified: bool,
    pub last_update: NaiveDateTime,
    pub last_authentication: NaiveDateTime,
    pub created: NaiveDateTime,
    pub disabled: bool,
}

impl EmailPassword {
    pub fn get_by_email(connection: DatabaseConnection, query_email: &str) -> AuthResult<Self> {
        let credential = diesel::QueryDsl::filter(
            crate::schema::email_password_credentials::table,
            email.eq(query_email),
        )
        .select(Self::as_select())
        .first(connection)?;

        // Checks if credential is disabled
        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }
}

impl Credential for EmailPassword {
    fn created(&self) -> &NaiveDateTime {
        &self.created
    }

    fn last_authentication(&self) -> &NaiveDateTime {
        &self.last_authentication
    }

    fn set_last_authentication(&mut self, connection: DatabaseConnection) -> AuthResult<()> {
        if self.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

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
        diesel::update(email_password_credentials.find(self.cid()))
            .set(self)
            .execute(connection)?;

        Ok(())
    }

    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()> {
        connection.transaction(|connection| {
            if !CredentialLookup::get_by_uid(connection, self.uid())?.has_multiple_credentials() {
                return Err(AuthError::CredentialCannotDelete);
            }

            diesel::delete(email_password_credentials.find(self.cid())).execute(connection)?;

            diesel::update(credentials.filter(email_password.eq(self.cid())))
                .set(email_password.eq(None::<Uuid>))
                .execute(connection)?;

            Ok(())
        })
    }

    fn cid(&self) -> &Uuid {
        &self.cid
    }

    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self> {
        let credential = email_password_credentials
            .find(query_cid)
            .select(Self::as_select())
            .first(connection)?;

        // Checks if credential is disabled
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
            crate::schema::email_password_credentials::table,
            email_password_credentials::dsl::uid.eq(query_uid),
        )
        .select(Self::as_select())
        .first(connection)?;

        // Checks if credential is disabled
        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }

    fn get_owner(&self, connection: DatabaseConnection) -> AuthResult<User> {
        User::get_by_uid(connection, &self.uid())
    }
}
