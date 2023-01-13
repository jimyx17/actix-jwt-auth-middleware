use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

/**
   A wrapper around the [`Authority`] which can be passed to the `wrap` function of a [`App`](actix_web::App)/[`Scope`](actix_web::Scope) or [`Resource`](actix_web::Resource).

   ## Example
   ```rust
   use actix_jwt_auth_middleware::{CookieSigner, Authority, AuthenticationService};
   use actix_web::{web, App};
   use serde::{Serialize, Deserialize};
   use exonum_crypto::KeyPair;
   use jwt_compact::{alg::Ed25519};

   #[derive(Serialize, Deserialize, Clone)]
   struct User {
       id: u32
   }

   let key_pair = KeyPair::random();

   let authority = Authority::<User, _, _, _>::new()
       .refresh_authorizer(|| async move { Ok(()) })
       .cookie_signer(Some(
           CookieSigner::new()
               .signing_key(key_pair.secret_key().clone())
               .algorithm(Ed25519)
               .build()
               .unwrap()
       ))
       .verifying_key(key_pair.public_key().clone())
       .build()
       .unwrap();

   let app = App::new()
       .service(
           web::scope("/auth-only")
               .wrap(
                   AuthenticationService::new(authority.clone())
               )
        );
   ```
*/
pub struct AuthenticationService<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    inner: Authority<Claims, Algorithm>,
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm>
    AuthenticationService<Claims, Algorithm>
where
    Claims: DeserializeOwned,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        returns a new AuthenticationService wrapping the [`Authority`]
    */
    pub fn new(
        authority: Authority<Claims, Algorithm>,
    ) -> AuthenticationService<Claims, Algorithm> {
        AuthenticationService {
            inner: authority,
            _claims: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm>
    Transform<S, ServiceRequest>
    for AuthenticationService<Claims, Algorithm>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
{
    type Response = <AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
    > as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform =
        AuthenticationMiddleware<S, Claims, Algorithm>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware::new(
            Rc::new(service),
            Arc::new(self.inner.clone()),
        ))
    }
}
