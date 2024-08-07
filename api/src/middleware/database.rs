use std::rc::Rc;

use actix_service::{Service, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    FromRequest, HttpMessage,
};
use futures::{
    future::{ready, LocalBoxFuture, Ready},
    FutureExt,
};

use crate::{
    database::{DatabaseConnection, DatabasePool},
    error::{ApiErrorType, ApiResult},
};

pub struct Middleware<S> {
    pub pool: DatabasePool,
    pub service: Rc<S>,
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

        req.extensions_mut()
            .insert::<DatabasePool>(self.pool.clone());

        async move {
            let response = service.call(req).await?;
            Ok(response)
        }
        .boxed_local()
    }
}

pub struct DatabaseMiddleware {
    pub pool: DatabasePool,
}

impl DatabaseMiddleware {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DatabaseMiddleware
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
            pool: self.pool.clone(),
            service: Rc::new(service),
        }))
    }
}

pub struct Database(DatabaseConnection);

impl Database {
    fn new(pool: &DatabasePool) -> ApiResult<Self> {
        Ok(Self(pool.get()?))
    }
}

impl FromRequest for Database {
    type Error = ApiErrorType;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let extensions = req.extensions();
        let pool = extensions.get::<DatabasePool>();
        ready(match pool {
            Some(pool) => Database::new(pool),
            None => Err(ApiErrorType::Unknown("Something went wrong!".into())),
        })
    }
}

impl std::ops::Deref for Database {
    type Target = DatabaseConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Database {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
