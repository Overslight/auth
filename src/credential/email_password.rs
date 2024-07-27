use super::{Credential, PartialCredential};
use crate::{
    credential::{CredentialLookup, InsertableCredentialLookup},
    database::DatabaseConnection,
    error::*,
    schema::{
        credentials::{self, email_password, uid},
        email_password_credentials,
    },
};
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
            Err(AuthError::NotFound)
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
        };

        Ok(connection.transaction(|connection| {
            let credential = diesel::insert_into(email_password_credentials::table)
                .values(&credential)
                .returning(EmailPassword::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: Some(credential.cid()),
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
}

impl<'a> From<&'a EmailPassword> for InsertableEmailPassword<'a> {
    fn from(value: &'a EmailPassword) -> Self {
        Self {
            cid: &value.cid,
            uid: &value.uid,
            email: &value.email,
            password: &value.password,
        }
    }
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = email_password_credentials)]
#[diesel(check_for_backend(Pg))]
pub struct EmailPassword {
    pub cid: Uuid,
    pub uid: Uuid,
    pub email: String,
    pub password: String,
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
}
