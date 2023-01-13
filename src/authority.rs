use std::marker::PhantomData;

use crate::{AuthError, AuthResult, CookieSigner};

use actix_web::{cookie::Cookie, dev::ServiceRequest, HttpMessage};
use derive_builder::Builder;
use jwt_compact::{
    AlgorithmExt, TimeOptions, Token, UntrustedToken,
};
use serde::{de::DeserializeOwned, Serialize};

macro_rules! pull_from_cookie_signer {
    ($self:ident ,$field_name:ident) => {
        match $self.cookie_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => {
                return ::derive_builder::export::core::result::Result::Err(
                    ::derive_builder::export::core::convert::Into::into(
                        ::derive_builder::UninitializedFieldError::from(stringify!($field_name)),
                    ),
                );
            }
        }
    };

    ($self:ident, $field_name:ident, $alternative:expr) => {
        match $self.cookie_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => $alternative,
        }
    };
}

#[doc(hidden)]
// struct used to signal to the middleware that a cookie needs to be updated
// after the wrapped service has returned a response.
#[derive(Debug)]
pub struct TokenUpdate {
    pub(crate) auth_cookie: Option<Cookie<'static>>,
}

/**
    Handles the authorization of requests for the middleware as well as refreshing the `access`/`refresh` token.

    Please referee to the [`AuthorityBuilder`] for a detailed description of options available on this struct.
*/
#[derive(Builder, Clone)]
pub struct Authority<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
       Not Passing a [`CookieSigner`] struct will make your middleware unable to refresh the access token automatically.

       You will have to provide a algorithm manually in this case because the Authority can not pull it from the `cookie_signer` field.

       Please referee to the structs own documentation for more details.
    */
    #[builder(default = "None")]
    cookie_signer: Option<CookieSigner<Claims, Algorithm>>,
    /**
        Depending on wether a [`CookieSigner`] is set, setting this field will have no affect.

        Defaults to the value of the `access_token_name` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this defaults to `"access_token"`.
    */
    #[builder(default = "pull_from_cookie_signer!(self, access_token_name, \"access_token\")")]
    pub(crate) access_token_name: &'static str,
    /**
        If set to true, the service will look for [`access_token_name`] and [`refresh_token_name`] in
        http headers.
     */
    #[builder(default = "false")]
    enable_header_tokens: bool,
    /**
        Key used to verify integrity of access and refresh token.
    */
    verifying_key: Algorithm::VerifyingKey,
    /**
        The Cryptographic signing algorithm used in the process of creation of access and refresh tokens.

        Please referee to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the `jwt-compact` crate
        for a comprehensive list of the supported algorithms.

        Defaults to the value of the `algorithm` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this field needs to be set.
    */
    #[builder(default = "pull_from_cookie_signer!(self, algorithm)")]
    algorithm: Algorithm,
    /**
        Used in the creating of the `token`, the current timestamp is taken from this, but please referee to the Structs documentation.

        Defaults to the value of the `time_options` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this field needs to be set.
    */
    #[builder(default = "pull_from_cookie_signer!(self, time_options)")]
    time_options: TimeOptions,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm> Authority<Claims, Algorithm>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        Returns a new [AuthorityBuilder]
    */
    pub fn new() -> AuthorityBuilder<Claims, Algorithm> {
        AuthorityBuilder::default()
    }

    /**
        Returns a Clone of the `cookie_signer` field on the Authority.
    */
    pub fn cookie_signer(&self) -> Option<CookieSigner<Claims, Algorithm>> {
        self.cookie_signer.clone()
    }

    /**
        Use by the [`crate::AuthenticationMiddleware`]
        in oder to verify an incoming request and ether hand it of to protected services
        or deny the request by return a wrapped [`AuthError`].
    */
    pub async fn verify_service_request(
        &self,
        req: ServiceRequest,
    ) -> AuthResult<(ServiceRequest, Option<TokenUpdate>)> {

        let access_token_value= get_token_value(&req, self.access_token_name, self.enable_header_tokens);

        match self.validate_token(&access_token_value) {
            Ok(access_token) => {
                req.extensions_mut()
                    .insert(access_token.claims().custom.clone());
                Ok((req, None))
            }
            Err(err) => Err(err)
        }
    }

    fn validate_token(&self, possible_token_value: &Option<String>) -> AuthResult<Token<Claims>> {
        match possible_token_value {
            Some(token_value) => match UntrustedToken::new(token_value) {
                Ok(untrusted_token) => {
                    match self
                        .algorithm
                        .validate_integrity::<Claims>(&untrusted_token, &self.verifying_key)
                    {
                        Ok(token) => match token.claims().validate_expiration(&self.time_options) {
                            Ok(_) => Ok(token),
                            Err(err) => Err(AuthError::TokenValidation(err)),
                        },
                        Err(err) => Err(err.into()),
                    }
                }
                Err(err) => Err(err.into()),
            },
            None => Err(AuthError::NoCookie),
        }
    }
}

fn get_token_value(req: &ServiceRequest, token_name: &str, enable_http_header: bool) -> Option<String> {
    match req.cookie(token_name) {
        Some(cookie) => Some(cookie.value().to_string()),
        None => {
            if enable_http_header {
                return get_header_value(token_name, req);
            }
            None
        }
    }
}

fn get_header_value(key: &str, req: &ServiceRequest) -> Option<String> {
    req.headers().get(key)?.to_str().ok().map(String::from)
}
