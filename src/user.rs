use crate::{
    credential::{Credential, CredentialLookup, PartialCredential},
    error::*,
    schema::credentials,
};
use diesel::{pg::Pg, prelude::*};
use uuid::Uuid;

use crate::{database::DatabaseConnection, schema::users};

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(Pg))]
pub struct User {
    pub uid: Uuid,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(Pg))]

struct InsertableUser<'a> {
    pub uid: &'a Uuid,
}

impl User {
    pub fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        Ok(users::table
            .find(query_uid)
            .select(User::as_select())
            .first(connection)?)
    }

    pub fn credentials(&self, connection: DatabaseConnection) -> AuthResult<CredentialLookup> {
        Ok(credentials::table
            .find(self.uid())
            .select(CredentialLookup::as_select())
            .first(connection)?)
    }

    pub fn new<T: Credential>(
        connection: DatabaseConnection,
        partial_credential: Option<Box<dyn PartialCredential<T>>>,
    ) -> AuthResult<Self> {
        Ok(connection.transaction(|connection| {
            // Creates the user
            let user = InsertableUser {
                uid: &Uuid::new_v4(),
            };

            let user = diesel::insert_into(users::table)
                .values(&user)
                .returning(User::as_returning())
                .get_result(connection)?;

            if let Some(partial_credential) = partial_credential {
                partial_credential
                    .associate(connection, user.uid())
                    .map_err(|_| diesel::result::Error::NotFound)?; // TODO: FIX ERROR TYPE
            }

            diesel::result::QueryResult::Ok(user)
        })?)
    }

    pub fn authenticate<T: Credential>(
        connection: DatabaseConnection,
        partial_credential: Box<dyn PartialCredential<T>>,
    ) -> AuthResult<Self> {
        let credential = partial_credential.authenticate(connection)?;
        Self::get_by_uid(connection, credential.uid())
    }

    pub fn uid(&self) -> &Uuid {
        &self.uid
    }
}
