use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use axum_extra::extract::CookieJar;
use http::header::AUTHORIZATION;
use http_auth_basic::Credentials;
use simple_safe::Safe;
use tracing::error;

pub use simple_safe as safe;

/// Used to extract a password authorized user.
pub struct Password(pub String);

impl<S> FromRequestParts<S> for Password
where
    S: Sync + AsRef<Safe>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cred = match parts.headers.get(AUTHORIZATION).map(|token| {
            token
                .to_str()
                .map(|b| Credentials::from_header(b.to_owned()))
        }) {
            Some(Ok(Ok(x))) => x,
            Some(_) => return Err(StatusCode::BAD_REQUEST),
            None => return Err(StatusCode::UNAUTHORIZED),
        };
        match state.as_ref().verify(&cred.user_id, &cred.password).await {
            Ok(true) => Ok(Password(cred.user_id)),
            Ok(false) | Err(simple_safe::Error::UserNotExist(_)) => Err(StatusCode::UNAUTHORIZED),
            Err(e) => {
                error!("{e}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

/// Used to extract a token authorized user.
pub struct Token(pub String);

impl<S> FromRequestParts<S> for Token
where
    S: Sync + AsRef<Safe>,
{
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = match jar.get("token") {
            Some(x) => x.value(),
            None => return Err(StatusCode::UNAUTHORIZED),
        };
        let user = match state.as_ref().verify_token(token) {
            Some(x) => x,
            None => return Err(StatusCode::UNAUTHORIZED),
        };
        Ok(Self(user))
    }
}
