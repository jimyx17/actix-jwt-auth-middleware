use crate::Authority;

use actix_web::{
    body::MessageBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    Error,
};
use futures_util::future::{FutureExt as _, LocalBoxFuture};
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

#[doc(hidden)]
pub struct AuthenticationMiddleware<S, Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<Claims, Algorithm>>,
    _claims: PhantomData<Claims>,
}

impl<S, Claims, Algorithm> AuthenticationMiddleware<S, Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(service: Rc<S>, inner: Arc<Authority<Claims, Algorithm>>) -> Self {
        Self {
            service,
            inner,
            _claims: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm> Service<ServiceRequest>
    for AuthenticationMiddleware<S, Claims, Algorithm>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
{
    type Response = ServiceResponse<Body>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);

        async move {
            match inner.verify_service_request(req).await {
                Ok((req, token_update)) => service.call(req).await.and_then(|mut res| {
                    if let Some(token_update) = token_update {
                        if let Some(auth_cookie) = token_update.auth_cookie {
                            res.response_mut().add_cookie(&auth_cookie)?
                        }
                    }
                    Ok(res)
                }),
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}
