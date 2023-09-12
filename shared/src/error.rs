use std::{io, fmt::{Display, Formatter}};

use actix_web::ResponseError;
use tokio::task::JoinError;

use crate::ballot::BallotSig;

#[derive(Debug)]
pub enum Error {
    SerializationError,
    IoError(io::Error),
    BlindRsaError(blind_rsa_signatures::Error),
    VoteNotFound,
    TaskError,
    BallotWrongSigType { expected: BallotSig, got: BallotSig },
    InvalidBallotOption,
    ReqwestError(reqwest::Error),
    BadBallotReceiptSignature,
    BallotNotFound,
    ClaimTokenProbablyUsed
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SerializationError => write!(f, "serialization error"),
            Error::IoError(e) => write!(f, "io error: {}", e),
            Error::BlindRsaError(e) => write!(f, "blind rsa error: {}", e),
            Error::VoteNotFound => write!(f, "vote not found"),
            Error::TaskError => write!(f, "task error"),
            Error::BallotWrongSigType { expected, got } => write!(
                f,
                "ballot has wrong sig type, expected {:?} got {:?}",
                expected, got
            ),
            Error::InvalidBallotOption => write!(f, "invalid ballot option"),
            Error::ReqwestError(e) => write!(f, "reqwest error: {}", e),
            Error::BadBallotReceiptSignature => write!(f, "bad ballot receipt signature"),
            Error::BallotNotFound => write!(f, "ballot not found"),
            Error::ClaimTokenProbablyUsed => write!(f, "claim token probably used"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<blind_rsa_signatures::Error> for Error {
    fn from(e: blind_rsa_signatures::Error) -> Self {
        Error::BlindRsaError(e)
    }
}

impl From<JoinError> for Error {
    fn from(_e: JoinError) -> Self {
        Error::TaskError
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::ReqwestError(e)
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Error::SerializationError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::IoError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::BlindRsaError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::VoteNotFound => actix_web::http::StatusCode::NOT_FOUND,
            Error::TaskError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::BallotWrongSigType { .. } => actix_web::http::StatusCode::BAD_REQUEST,
            Error::InvalidBallotOption => actix_web::http::StatusCode::BAD_REQUEST,
            Error::ReqwestError(_) => unreachable!(),
            Error::BadBallotReceiptSignature => unreachable!(),
            Error::BallotNotFound => actix_web::http::StatusCode::NOT_FOUND,
            Error::ClaimTokenProbablyUsed => actix_web::http::StatusCode::CONFLICT,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let mut builder = actix_web::HttpResponse::build(self.status_code());
        builder.content_type("text/plain");
        builder.body(actix_web::body::BoxBody::new(self.to_string()))
    }
}