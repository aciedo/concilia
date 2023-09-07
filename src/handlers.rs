use std::sync::Arc;

use actix_web::{post, web, Responder, get, ResponseError};
use blind_rsa_signatures::{Options, BlindedMessage, reexports::rsa::{self, pkcs8::DecodePublicKey}, Signature, MessageRandomizer, PublicKey as RsaPublicKey};
use kt2::SecretKey;
use rkyv::{archived_root, from_bytes};
use tracing::info;

use crate::{DbGetter, shared::{Error, Vote, VoteID, BallotToken, Ballot, BallotID, BallotSig, AsString}, db::{FLUSH_NOTIFY, store_vote, store_vote_sk, maybe_read_vote_sk, maybe_read_vote, store_ballot, apply_ballot}};

#[post("/create_vote")]
async fn create_vote(
    options: web::Json<Vec<String>>,
    db_tx: web::Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let flush_notify = FLUSH_NOTIFY.clone();
    let (sk, vote) = Vote::new(options.0).unwrap();
    let vote_id = store_vote(&vote, &db)?;
    store_vote_sk(&sk, &vote_id, &db)?;
    flush_notify.notified().await;
    info!("SERVER vote created: {}", &vote_id);
    Ok(web::Json(vote_id.to_string()))
}

// // 2. VOTER authenticates themselves to receive a blinded signature signed by vote's secret key
// // This would usually include some sort of ID check. Personal info is okay-ish to hand over
// // because the server can't link blind_msg to the submitted ballot
// let vote_id = VoteID::new(&vote);
// let claim_token = b"1234";
// let vote_pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
// let blinding_result = vote_pk.blind(rng, claim_token, true, &options)?;
// let blind_msg = blinding_result.blind_msg.clone();
// info!(
//     "VOTER created blind msg: {}",
//     bs58::encode(&blind_msg).into_string()
// );
// // blind_msg -> SERVER

#[post("/verify_eligibility")]
async fn verify_eligibility(
    body: web::Json<(VoteID, Vec<u8>)>,
    db_tx: web::Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    // load params from body
    let (vote_id, blind_msg) = body.0;
    let options = Options::default();
    let rng = &mut rand::thread_rng();
    let blind_msg = BlindedMessage(blind_msg);
    info!("SERVER loading vote blinding secret key");
    let sk = maybe_read_vote_sk(&vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
    let sig = sk.blind_sign(rng, &blind_msg, &options)?;
    let token = BallotToken::new(sig);
    info!(
        "SERVER issued ballot token: {}",
        bs58::encode(&token.blinded_sig).into_string()
    );
    Ok(web::Json(token.as_string()))
}

// // 3. Voter unblinds the token into a signature
// // VOTER
// info!("VOTER unblinding ballot token");
// let opt = "Bob".to_string();
// let mut ballot = Ballot::from_token(
//     token,
//     opt,
//     &blinding_result,
//     claim_token,
//     &options,
//     &vote_pk,
//     &vote_id,
// )
// .unwrap();
// info!("VOTER created unblinded ballot");
// // ballot -> SERVER

#[post("/submit_ballot")]
async fn submit_ballot(
    body: web::Json<(Ballot, Option<[u8; 32]>, [u8; 32])>,
    db_tx: web::Data<DbGetter>,
    kt2_secret: web::Data<Arc<SecretKey>>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    // load options from body
    let (mut ballot, msg_randomizer, claim_token) = body.0;
    let options = Options::default();
    // try read vote from db
    let vote_bytes = maybe_read_vote(&ballot.vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
    // unsafe vote parsing
    let vote = unsafe { archived_root::<Vote>(&vote_bytes[..]) };
    let ballot_id = BallotID::new(&ballot);
    let pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
    info!("SERVER validating blind signature");

    let sig = if let BallotSig::Blind(sig) = ballot.sig {
        sig
    } else {
        return Err(Error::BallotWrongSigType {
            expected: BallotSig::Blind(vec![]),
            got: ballot.sig,
        });
    };
    Signature::from(sig).verify(
        &pk,
        msg_randomizer.map(|r| MessageRandomizer::new(r)),
        claim_token,
        &options,
    )?;
    info!("SERVER blind signature valid");
    // this is your "vote counted" receipt
    // we replace the blind sig with a D3 sig because PQ blind sigs are huge (22kb each) so we don't bother storing them
    let kt2_sig = kt2_secret.sign(&ballot_id.0).0.to_vec();
    ballot.sig = BallotSig::D3(kt2_sig.clone());
    let flush_notify = FLUSH_NOTIFY.clone();
    store_ballot(&ballot, &ballot_id, &db)?;
    apply_ballot(&ballot.vote_id, &ballot, db.clone())?;
    flush_notify.notified().await;
    info!("SERVER counted ballot");
    Ok(web::Json((ballot_id.as_string(), bs58::encode(&kt2_sig).into_string())))
}

#[get("/get_votes")]
async fn get_votes(db_tx: web::Data<DbGetter>) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let votes = db.scan_prefix(b"vote_").map(|v| {
        let (k, v) = v.unwrap();
        let vote_id = VoteID {
            hash: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&k[5..]);
                h
            }
        };
        let vote: Vote = from_bytes(&v).unwrap();
        (vote_id.to_string(), vote)
    }).collect::<Vec<_>>();
    Ok(web::Json(votes))
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
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let mut builder = actix_web::HttpResponse::build(self.status_code());
        builder.content_type("text/plain");
        builder.body(actix_web::body::BoxBody::new(self.to_string()))
    }
}