use std::{ops::Deref, rc::Rc};

use actix_identity::{Identity, IdentityExt};
use actix_service::Transform;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse},
    web, FromRequest, HttpMessage,
};
use auth::user::User;
use futures::{
    future::{ready, LocalBoxFuture, Ready},
    FutureExt,
};
use uuid::Uuid;

use crate::{
    database::DatabasePool,
    error::{ApiErrorType, ApiResult},
};

pub struct Middleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for Middleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        async move {
            let id = req.get_identity().ok();

            if let Some(id) = id {
                req.extensions_mut().insert::<Identity>(id);
            }

            let response = service.call(req).await?;

            Ok(response)
        }
        .boxed_local()
    }
}

pub struct AuthenticationMiddleware {}

impl AuthenticationMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthenticationMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = Middleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(Middleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AllowAuthenticated(pub Option<User>);

impl AllowAuthenticated {
    pub async fn new(identity: Option<&Identity>, pool: Option<DatabasePool>) -> ApiResult<Self> {
        let identity = match identity {
            Some(identity) => identity,
            None => return Ok(Self(None)),
        };

        let pool = pool.ok_or(ApiErrorType::Unknown("Something went wrong!".into()))?;

        let uid = Uuid::parse_str(identity.id()?.as_str())?;

        let user = web::block::<_, ApiResult<Option<User>>>(move || {
            let mut connection = pool.get()?;
            User::get_by_uid(&mut connection, &uid)
                .map(|user| Some(user))
                .map_err(ApiErrorType::from)
        })
        .await??;

        Ok(Self(user))
    }
}

impl FromRequest for AllowAuthenticated {
    type Error = ApiErrorType;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let req = req.to_owned();

        async move {
            let extensions = req.extensions();
            let identity = extensions.get::<Identity>();
            let pool = extensions.get::<DatabasePool>().map(ToOwned::to_owned);

            Self::new(identity, pool).await
        }
        .boxed_local()
    }
}

impl Deref for AllowAuthenticated {
    type Target = Option<User>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct RequireAuthenticated(User);

impl RequireAuthenticated {
    pub async fn new(identity: Option<&Identity>, pool: Option<DatabasePool>) -> ApiResult<Self> {
        let identity = identity.ok_or(ApiErrorType::CredentialIncorrect)?;

        let pool = pool.ok_or(ApiErrorType::Unknown("Something went wrong!".into()))?;

        let uid = Uuid::parse_str(identity.id()?.as_str())?;

        let user = web::block::<_, ApiResult<User>>(move || {
            let mut connection = pool.get()?;
            User::get_by_uid(&mut connection, &uid).map_err(ApiErrorType::from)
        })
        .await??;

        Ok(Self(user))
    }
}

impl FromRequest for RequireAuthenticated {
    type Error = ApiErrorType;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let req = req.to_owned();

        async move {
            let extensions = req.extensions();
            let identity = extensions.get::<Identity>();
            let pool = extensions.get::<DatabasePool>().map(ToOwned::to_owned);

            Self::new(identity, pool).await
        }
        .boxed_local()
    }
}

impl Deref for RequireAuthenticated {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct DenyAuthenticated {}

impl FromRequest for DenyAuthenticated {
    type Error = ApiErrorType;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let extensions = req.extensions();
        let identity = extensions.get::<Identity>();

        ready(match identity {
            Some(_) => Err(ApiErrorType::UserAuthenticated),
            None => Ok(DenyAuthenticated {}),
        })
    }
}
