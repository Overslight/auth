use chrono::{NaiveDateTime, Utc};
use diesel::pg::Pg;
use diesel::{prelude::*, QueryDsl, Selectable};
use uuid::Uuid;

use crate::error::AuthError;
use crate::user::User;
use crate::{
    database::DatabaseConnection,
    schema::{
        credentials::{self, github_oauth, uid},
        github_oauth_credentials::{self, provider_id},
    },
};

use super::{
    AuthResult, Credential, CredentialLookup, InsertableCredentialLookup, PartialCredential,
};

pub struct PartialGithubOauth {
    pub provider_id: i32,
    pub email: String,
}

impl PartialGithubOauth {
    pub fn new(query_provider_id: i32, email: String) -> Self {
        Self {
            provider_id: query_provider_id,
            email,
        }
    }
}

impl PartialCredential<GithubOauth> for PartialGithubOauth {
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<GithubOauth> {
        GithubOauth::get_by_provider_id(connection, self.provider_id)
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<GithubOauth> {
        let credential = InsertableGithubOauth {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            provider_id: self.provider_id,
            email: &self.email,
            last_authentication: &Utc::now().naive_utc(),
            created: &Utc::now().naive_utc(),
        };

        Ok(connection.transaction(|connection| {
            let credential = diesel::insert_into(github_oauth_credentials::table)
                .values(&credential)
                .returning(GithubOauth::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: None,
                github_oauth: Some(credential.cid()),
            };

            diesel::insert_into(credentials::table)
                .values(&credential_lookup)
                .on_conflict(uid)
                .do_update()
                .set(github_oauth.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            diesel::result::QueryResult::Ok(credential)
        })?)
    }
}

#[derive(Insertable)]
#[diesel(table_name = github_oauth_credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableGithubOauth<'a> {
    pub cid: &'a Uuid,
    pub uid: &'a Uuid,
    pub provider_id: i32,
    pub email: &'a String,
    pub last_authentication: &'a NaiveDateTime,
    pub created: &'a NaiveDateTime,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = github_oauth_credentials)]
#[diesel(check_for_backend(Pg))]
pub struct GithubOauth {
    pub cid: Uuid,
    pub uid: Uuid,
    pub provider_id: i32,
    pub email: String,
    pub last_authentication: NaiveDateTime,
    pub created: NaiveDateTime,
}

impl GithubOauth {
    pub fn get_by_provider_id(
        connection: DatabaseConnection,
        query_provider_id: i32,
    ) -> AuthResult<Self> {
        Ok(diesel::QueryDsl::filter(
            crate::schema::github_oauth_credentials::table,
            provider_id.eq(query_provider_id),
        )
        .select(GithubOauth::as_select())
        .first(connection)?)
    }
}

impl Credential for GithubOauth {
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
        use crate::schema::github_oauth_credentials::dsl::*;

        Ok(github_oauth_credentials
            .find(query_cid)
            .select(GithubOauth::as_select())
            .first(connection)?)
    }

    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self> {
        use crate::schema::github_oauth_credentials::dsl::*;

        Ok(diesel::QueryDsl::filter(
            crate::schema::github_oauth_credentials::table,
            uid.eq(query_uid),
        )
        .select(GithubOauth::as_select())
        .first(connection)?)
    }

    fn delete(&self, connection: DatabaseConnection) -> AuthResult<()> {
        connection.transaction(|connection| {
            use crate::schema::{credentials::dsl::*, github_oauth_credentials::dsl::*};

            if !CredentialLookup::get_by_uid(connection, self.uid())?.has_multiple_credentials() {
                return Err(AuthError::CredentialCannotDelete);
            }

            diesel::delete(github_oauth_credentials.find(self.cid())).execute(connection)?;

            diesel::update(credentials.filter(github_oauth.eq(self.cid())))
                .set(github_oauth.eq(None::<Uuid>))
                .execute(connection)?;

            Ok(())
        })
    }

    fn get_owner(&self, _connection: DatabaseConnection) -> AuthResult<User> {
        todo!()
    }
}
