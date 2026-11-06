//! The relay's error model (SPEC §7.8): a closed set of codes, one JSON shape,
//! and nothing that explains *why* an authentication or lookup failed.
//!
//! ```json
//! { "error": "invalid_request" }
//! ```
//!
//! No stack traces, no account identifiers, no internal ids. A `401` covers
//! both "bad token" and "unknown account"; a `404` covers both "no such vault"
//! and "not yours".

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Every error the relay can answer with (SPEC §7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// Malformed input: unknown field, wrong type, bad id, bad media type.
    InvalidRequest,
    /// Bad token, unknown account, expired or revoked session.
    Unauthorized,
    /// Authenticated but not allowed (revoked device, tombstoned account).
    Forbidden,
    /// No such vault, or a vault that belongs to someone else.
    NotFound,
    /// Compare-and-swap mismatch, duplicate `op_id` with different bytes.
    Conflict,
    /// Body over the cap.
    TooLarge,
    /// Account storage quota exceeded.
    QuotaExceeded,
    /// Rate limit hit.
    RateLimited,
    /// Something failed on our side. Details go to the log, never the client.
    Unavailable,
}

impl ApiError {
    /// The machine-readable code.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TooLarge => "too_large",
            Self::QuotaExceeded => "quota_exceeded",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
        }
    }

    /// The HTTP status that goes with the code (SPEC §7.2, §7.7, §7.8).
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::QuotaExceeded => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The response body.
    pub fn body(self) -> ErrorBody {
        ErrorBody { error: self.code() }
    }
}

/// The only error shape the relay answers with.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut response = (status, Json(self.body())).into_response();
        if self == Self::RateLimited {
            // §7.7: Retry-After where meaningful. One minute is a safe floor
            // for every limited operation in v1.
            if let Ok(value) = "60".parse() {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        response
    }
}

/// The result type handlers return. Used by every endpoint from step 2 on.
#[allow(dead_code)]
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::RETRY_AFTER;

    #[test]
    fn every_code_is_in_the_closed_set() {
        let codes = [
            ApiError::InvalidRequest,
            ApiError::Unauthorized,
            ApiError::Forbidden,
            ApiError::NotFound,
            ApiError::Conflict,
            ApiError::TooLarge,
            ApiError::QuotaExceeded,
            ApiError::RateLimited,
            ApiError::Unavailable,
        ]
        .map(|error| error.code());
        let expected = [
            "invalid_request",
            "unauthorized",
            "forbidden",
            "not_found",
            "conflict",
            "too_large",
            "quota_exceeded",
            "rate_limited",
            "unavailable",
        ];
        assert_eq!(codes, expected);
    }

    #[test]
    fn statuses_match_the_spec() {
        assert_eq!(ApiError::InvalidRequest.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::Conflict.status(), StatusCode::CONFLICT);
        assert_eq!(ApiError::TooLarge.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            ApiError::QuotaExceeded.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ApiError::RateLimited.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::Unavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn rate_limited_carries_retry_after() {
        let response = ApiError::RateLimited.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).expect("header"), "60");
        let other = ApiError::Unauthorized.into_response();
        assert!(other.headers().get(RETRY_AFTER).is_none());
    }

    #[test]
    fn the_body_has_exactly_one_field() {
        assert_eq!(
            serde_json::to_value(ApiError::Unauthorized.body()).expect("json"),
            serde_json::json!({ "error": "unauthorized" })
        );
    }
}
