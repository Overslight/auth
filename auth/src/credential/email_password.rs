use super::{Credential, PartialCredential};
use crate::{
    credential::{CredentialLookup, InsertableCredentialLookup},
    database::DatabaseConnection,
    error::*,
    schema::{
        credentials::{self, email_password, uid},
        email_password_credentials,
    }, user::User,
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
    pub fn new(email: String, password: String) -> Self {
        Self { email, password }
    }
}

impl PartialCredential<EmailPassword> for PartialEmailPassword {
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<EmailPassword> {
        let credential = EmailPassword::get_by_email(connection, &self.email)?;
        let valid_password = Argon2::default()
            .verify_password(
                self.password.as_bytes(),
                &PasswordHash::new(&credential.password)?,
            )
            .is_ok();

        if valid_password {
            Ok(credential)
        } else {
            Err(AuthError::NotFound("Incorrect email or password!".into()))
        }
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<EmailPassword> {
        let hashed_password = Argon2::default()
            .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))?
            .to_string();

        let credential = InsertableEmailPassword {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            email: &self.email,
            password: &hashed_password,
            verified: false,
            last_update: &Utc::now().naive_utc(),
            last_authentication: &Utc::now().naive_utc(),
            created: &Utc::now().naive_utc(),
        };

        Ok(connection.transaction(|connection| {
            let credential = diesel::insert_into(email_password_credentials::table)
                .values(&credential)
                .returning(EmailPassword::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: Some(credential.cid()),
                github_oauth: None,
            };

            diesel::insert_into(credentials::table)
                .values(&credential_lookup)
                .on_conflict(uid)
                .do_update()
                .set(email_password.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            diesel::result::QueryResult::Ok(credential)
        })?)
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
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = email_password_credentials)]
#[diesel(check_for_backend(Pg))]
pub struct EmailPassword {
    pub cid: Uuid,
    pub uid: Uuid,
    pub email: String,
    pub password: String,
    pub verified: bool,
    pub last_update: NaiveDateTime,
    pub last_authentication: NaiveDateTime,
    pub created: NaiveDateTime,
}

impl EmailPassword {
    pub fn get_by_email(connection: DatabaseConnection, query_email: &str) -> AuthResult<Self> {
        use crate::schema::email_password_credentials::dsl::*;

        Ok(diesel::QueryDsl::filter(
            crate::schema::email_password_credentials::table,
            email.eq(query_email),
        )
        .select(EmailPassword::as_select())
        .first(connection)?)
    }
}

impl Credential for EmailPassword {
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
        use crate::schema::email_password_credentials::dsl::*;

        Ok(email_password_credentials
            .find(query_cid)
            .select(EmailPassword::as_select())
            .first(connection)?)
    }

    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        use crate::schema::email_password_credentials::dsl::*;

        Ok(diesel::QueryDsl::filter(
            crate::schema::email_password_credentials::table,
            uid.eq(query_uid),
        )
        .select(EmailPassword::as_select())
        .first(connection)?)
    }

    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()> {
        connection.transaction(|connection| {
            use crate::schema::{credentials::dsl::*, email_password_credentials::dsl::*};

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

    fn get_owner(&self, _connection: DatabaseConnection) -> AuthResult<User> {
        todo!()
    }
}
