use crate::{
    credential::{Credential, CredentialLookup, PartialCredential},
    error::*,
};
use diesel::{pg::Pg, prelude::*};
use serde::Serialize;
use uuid::Uuid;

use crate::{database::DatabaseConnection, schema::users};

#[derive(Queryable, Selectable, Debug, Serialize)]
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
        users::table
            .find(query_uid)
            .select(User::as_select())
            .first(connection)
            .map_err(AuthError::from)
    }

    pub fn credentials(&self, connection: DatabaseConnection) -> AuthResult<CredentialLookup> {
        CredentialLookup::get_by_uid(connection, self.uid())
    }

    pub fn new<C: Credential, P: PartialCredential<C>>(
        connection: DatabaseConnection,
        partial_credential: P,
    ) -> AuthResult<Self> {
        Ok(connection.transaction::<User, AuthError, _>(|connection| {
            // Creates the user
            let user = InsertableUser {
                uid: &Uuid::new_v4(),
            };

            let user = diesel::insert_into(users::table)
                .values(&user)
                .returning(User::as_returning())
                .get_result(connection)?;

            partial_credential.associate(connection, user.uid())?;

            Ok(user)
        })?)
    }

    pub fn authenticate<C: Credential, P: PartialCredential<C>>(
        connection: DatabaseConnection,
        partial_credential: P,
    ) -> AuthResult<Self> {
        let credential = partial_credential.authenticate(connection)?;
        Self::get_by_uid(connection, credential.uid())
    }

    pub fn uid(&self) -> &Uuid {
        &self.uid
    }
}
