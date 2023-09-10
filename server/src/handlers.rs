use actix_web::{get, post, web::{self, Json, Data}, Responder};
use blind_rsa_signatures::{
    reexports::rsa::{self, pkcs8::DecodePublicKey},
    BlindedMessage, MessageRandomizer, Options, PublicKey as RsaPublicKey, Signature,
};
use kt2::{PublicKey, SecretKey};
use rkyv::{archived_root, from_bytes};
use serde::Deserialize as De;
use tokio::sync::RwLock;
use tracing::trace;

use crate::{
    db::{
        apply_ballot, maybe_read_ballot, maybe_read_vote, maybe_read_vote_sk, store_ballot,
        store_vote, store_vote_sk, CHECKPOINT, store_filter,
    },
    DbGetter, cuckoo::ScalableCuckooFilter,
};
use concilia_shared::{
    Ballot, BallotID, BallotSig, BallotToken, Error, StringConversion, Vote, VoteID,
};

#[get("/kt2_public")]
async fn kt2_public(public: Data<PublicKey>) -> Result<impl Responder, Error> {
    Ok(Json(bs58::encode(public.bytes).into_string()))
}

#[post("/create_vote")]
async fn create_vote(
    options: Json<(String, String, Vec<String>)>,
    db_tx: Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let (title, desc, options) = options.0;
    let (sk, vote) = Vote::new(title, desc, options).unwrap();
    let vote_id = store_vote(&vote, &db)?;
    store_vote_sk(&sk, &vote_id, &db)?;
    CHECKPOINT.clone().notified().await;
    trace!("SERVER vote created: {}", &vote_id);
    Ok(Json(vote_id.to_string()))
}

#[post("/verify_eligibility")]
async fn verify_eligibility(
    body: Json<(VoteID, Vec<u8>)>,
    db_tx: Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    // load params from body
    let (vote_id, blind_msg) = body.0;
    let options = Options::default();
    let rng = &mut rand::thread_rng();
    let blind_msg = BlindedMessage(blind_msg);
    trace!("SERVER loading vote blinding secret key");
    let sk = maybe_read_vote_sk(&vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
    let sig = sk.blind_sign(rng, &blind_msg, &options)?;
    let token = BallotToken::new(sig);
    trace!(
        "SERVER issued ballot token: {}",
        bs58::encode(&token.blinded_sig).into_string()
    );
    Ok(Json(token.as_string()))
}

#[post("/submit_ballot")]
async fn submit_ballot(
    body: Json<(VoteID, Ballot, Option<[u8; 32]>, [u8; 32])>,
    db_tx: Data<DbGetter>,
    kt2_secret: Data<SecretKey>,
    filter: Data<RwLock<ScalableCuckooFilter<[u8; 32]>>>
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    // load options from body
    let (vote_id, mut ballot, msg_randomizer, claim_token) = body.0;
    if filter.read().await.contains(&claim_token) {
        return Err(Error::ClaimTokenProbablyUsed);
    }
    
    let options = Options::default();
    // try read vote from db
    let vote_bytes = maybe_read_vote(&vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
    // unsafe vote parsing
    let vote = unsafe { archived_root::<Vote>(&vote_bytes[..]) };

    let ballot_id = BallotID::new(&ballot);
    let pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
    trace!("SERVER validating blind signature");

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
    trace!("SERVER blind signature valid");
    // this is your "vote counted" receipt
    // we replace the blind sig with a D3 sig because PQ blind sigs are huge (22kb each) so we don't bother storing them
    let kt2_sig = kt2_secret.sign(&ballot_id.0).0.to_vec();
    let kt2_str = bs58::encode(&kt2_sig).into_string();
    ballot.sig = BallotSig::D3(kt2_sig);
    let mut filter = filter.write().await;
    for (filter, index) in filter.insert(&claim_token) {
        store_filter(filter, index, &db)?;
    }
    drop(filter);
    store_ballot(&ballot, &ballot_id, &vote_id, &db)?;
    apply_ballot(&vote_id, &ballot, db.clone())?;
    CHECKPOINT.clone().notified().await;
    trace!("SERVER counted ballot");
    Ok(Json((ballot_id.as_string(), kt2_str)))
}

#[get("/votes")]
async fn get_votes(
    db_tx: Data<DbGetter>,
    query: web::Query<Paging>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let mut iter = db.scan_prefix(b"vote_");

    if let Err(_) = iter.advance_by(query.page.unwrap_or(0) * query.limit.unwrap_or(10)) {
        return Ok(Json(vec![]));
    };

    let votes = iter
        .take(query.limit.unwrap_or(10))
        .map(|v| {
            let (k, v) = v.unwrap();
            let vote_id = VoteID {
                hash: {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k[5..]);
                    h
                },
            };
            let vote: Vote = from_bytes(&v).unwrap();
            (vote_id.to_string(), vote)
        })
        .collect::<Vec<_>>();
    Ok(Json(votes))
}

#[get("/vote/{vote_id}")]
async fn get_vote(
    vote_id: web::Path<String>,
    db_tx: Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let vote_id = VoteID::from_string(vote_id.to_string()).ok_or(Error::SerializationError)?;
    let vote_bytes = maybe_read_vote(&vote_id, db)
        .await?
        .ok_or(Error::VoteNotFound)?;
    let vote: Vote = from_bytes(&vote_bytes).unwrap();
    Ok(Json(vote))
}

#[get("/vote/{vote_id}/ballot/{ballot_id}")]
async fn get_ballot(
    path: web::Path<(String, String)>,
    db_tx: Data<DbGetter>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let (vote_id, ballot_id) = path.into_inner();
    let vote_id = VoteID::from_string(vote_id.to_string()).ok_or(Error::SerializationError)?;
    let ballot_id =
        BallotID::from_string(ballot_id.to_string()).ok_or(Error::SerializationError)?;
    let ballot_bytes = maybe_read_ballot(&vote_id, &ballot_id, db)
        .await?
        .ok_or(Error::BallotNotFound)?;
    let ballot: Ballot = from_bytes(&ballot_bytes).unwrap();
    Ok(Json(ballot))
}

#[derive(De)]
pub struct Paging {
    limit: Option<usize>,
    page: Option<usize>,
}

#[get("/vote/{vote_id}/ballots")]
async fn get_ballots(
    vote_id: web::Path<String>,
    db_tx: Data<DbGetter>,
    query: web::Query<Paging>,
) -> Result<impl Responder, Error> {
    let db = db_tx.get().await;
    let vote_id = VoteID::from_string(vote_id.to_string()).ok_or(Error::SerializationError)?;
    let mut iter = db.scan_prefix([vote_id.as_ref(), b"_ballot_"].concat());
    if let Err(_) = iter.advance_by(query.page.unwrap_or(0) * query.limit.unwrap_or(10)) {
        return Ok(Json(vec![]));
    };

    let ballots = iter
        .take(query.limit.unwrap_or(10))
        .map(|v| {
            let (k, v) = v.unwrap();
            let ballot_id = BallotID({
                let mut h = [0u8; 32];
                h.copy_from_slice(&k[40..]);
                h
            });

            let ballot: Ballot = from_bytes(&v).unwrap();
            (ballot_id.to_string(), ballot)
        })
        .collect::<Vec<_>>();
    Ok(Json(ballots))
}
