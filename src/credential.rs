use crate::schema::credentials;
use crate::{database::DatabaseConnection, error::*};
use diesel::pg::Pg;
use diesel::prelude::*;
use uuid::Uuid;

pub mod email_password;

pub trait Credential
where
    Self: Sized,
{
    fn cid(&self) -> &Uuid;
    fn uid(&self) -> &Uuid;
    fn get_by_cid(connection: DatabaseConnection, query_cid: &Uuid) -> AuthResult<Self>;
    fn get_by_uid(connection: DatabaseConnection, query_uid: &Uuid) -> AuthResult<Self>;
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
}

#[derive(Insertable, Debug)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(Pg))]
struct InsertableCredentialLookup<'a> {
    pub uid: &'a Uuid,
    pub email_password: Option<&'a Uuid>,
}
