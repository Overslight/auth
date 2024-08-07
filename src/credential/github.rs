use chrono::{NaiveDateTime, Utc};
use diesel::pg::Pg;
use diesel::{prelude::*, QueryDsl, Selectable};
use uuid::Uuid;

use crate::error::AuthError;
use crate::user::User;
use crate::{
    database::DatabaseConnection,
    schema::{
        credentials::{self, dsl::*},
        github_oauth_credentials::{self, dsl::*},
    },
};

use super::{
    AuthResult, Credential, CredentialLookup, InsertableCredentialLookup, PartialCredential,
};

pub struct PartialGithubOauth {
    pub provider_id: i32,
    pub username: String,
}

impl PartialGithubOauth {
    pub fn new(partial_provider_id: i32, partial_username: String) -> Self {
        Self {
            provider_id: partial_provider_id,
            username: partial_username,
        }
    }
}

impl PartialCredential<GithubOauth> for PartialGithubOauth {
    fn authenticate(&self, connection: DatabaseConnection) -> AuthResult<GithubOauth> {
        let mut credential = GithubOauth::get_by_provider_id(connection, self.provider_id)?;
        
        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }
        
        credential.set_last_authentication(connection)?;

        Ok(credential)
    }

    fn associate(
        &self,
        connection: DatabaseConnection,
        owner_uid: &Uuid,
    ) -> AuthResult<GithubOauth> {
        let timestamp = Utc::now().naive_utc();
        let credential = InsertableGithubOauth {
            cid: &Uuid::new_v4(),
            uid: owner_uid,
            provider_id: self.provider_id,
            username: &self.username,
            last_authentication: &timestamp,
            last_update: &timestamp,
            created: &timestamp,
            disabled: false,
        };

        connection.transaction::<GithubOauth, AuthError, _>(|connection| {
            let credential = diesel::insert_into(github_oauth_credentials::table)
                .values(&credential)
                .returning(GithubOauth::as_returning())
                .get_result(connection)?;

            let credential_lookup = InsertableCredentialLookup {
                uid: owner_uid,
                email_password: None,
                github_oauth: Some(credential.cid()),
                username_password: None,
            };

            diesel::insert_into(credentials::table)
                .values(&credential_lookup)
                .on_conflict(credentials::dsl::uid)
                .do_update()
                .set(github_oauth.eq(credential.cid()))
                .returning(CredentialLookup::as_returning())
                .get_result(connection)?;

            Ok(credential)
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = github_oauth_credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableGithubOauth<'a> {
    pub cid: &'a Uuid,
    pub uid: &'a Uuid,
    pub provider_id: i32,
    pub username: &'a String,
    pub last_authentication: &'a NaiveDateTime,
    pub last_update: &'a NaiveDateTime,
    pub created: &'a NaiveDateTime,
    pub disabled: bool,
}

#[derive(Queryable, AsChangeset, Selectable)]
#[diesel(table_name = github_oauth_credentials)]
#[diesel(check_for_backend(Pg))]
#[diesel(primary_key(cid))]
pub struct GithubOauth {
    pub cid: Uuid,
    pub uid: Uuid,
    pub provider_id: i32,
    pub username: String,
    pub last_authentication: NaiveDateTime,
    pub last_update: NaiveDateTime,
    pub created: NaiveDateTime,
    pub disabled: bool,
}

impl GithubOauth {
    pub fn get_by_provider_id(
        connection: DatabaseConnection,
        query_provider_id: i32,
    ) -> AuthResult<Self> {
        let credential = diesel::QueryDsl::filter(
            crate::schema::github_oauth_credentials::table,
            provider_id.eq(query_provider_id),
        )
        .select(Self::as_select())
        .first(connection)?;

        if credential.disabled() {
            return Err(AuthError::CredentialDisabled);
        }

        Ok(credential)
    }
}

impl Credential for GithubOauth {
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
        true
    }

    fn set_verified(
        &mut self,
        _connection: DatabaseConnection,
        _updated_verified: bool,
    ) -> AuthResult<()> {
        unimplemented!()
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
        diesel::update(github_oauth_credentials.find(self.cid()))
            .set(self)
            .execute(connection)?;

        Ok(())
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

    fn cid(&self) -> &Uuid {
        &self.cid
    }

    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self> {
        let credential = github_oauth_credentials
            .find(query_cid)
            .select(Self::as_select())
            .first(connection)?;

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
            crate::schema::github_oauth_credentials::table,
            github_oauth_credentials::dsl::uid.eq(query_uid),
        )
        .select(Self::as_select())
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
