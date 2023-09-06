#![feature(lazy_cell)]
use std::{
    io,
    sync::{Arc, LazyLock},
};

use blake3::{hash, Hasher};
use blind_rsa_signatures::{
    reexports::rsa::{
        self,
        pkcs8::{DecodePublicKey, EncodePublicKey},
    },
    BlindSignature, BlindingResult, KeyPair, Options, PublicKey as RsaPublicKey,
    SecretKey as RsaSecretKey, Signature,
};
use kt2::{SIGN_BYTES, Keypair};
use rkyv::{archived_root, to_bytes, Archive, Deserialize, Serialize};
use sled::{Db, InlineArray};
use tokio::sync::Notify;

// 1. Create vote
// 2. Voter authenticates themselves to receive a blinded signature signed by vote's secret key
// 3. Voter unblinds signature
// 4. Voter submits vote and unblinded signature
// 5. Server signs the ballot using KT2-D3, replacing the blind sig with a regular sig (a lot smaller)
// 6. Server stores the ballot in the database
// 7. HTTP call awaits fsync to ensure the ballot is stored on disk
// 8. Server returns the ballot ID to the voter

#[tokio::main]
async fn main() -> Result<(), Error> {
    let db = sled::Config::default()
        .flush_every_ms(None)
        .path("concilia.db")
        .open()?;
    println!("db opened");
    let rng = &mut rand::thread_rng();
    Flusher::new(FLUSH_NOTIFY.clone()).start(db.clone());
    
    let Keypair { secret, public } = Keypair::generate(None);

    // 1. Create vote on SERVER
    let (sk, vote) = Vote::new(vec!["Bob".to_string()]).unwrap();
    store_vote(&vote, &db).await?;
    println!("created vote");

    // 2. VOTER authenticates themselves to receive a blinded signature signed by vote's secret key
    // This would usually include some sort of ID check
    let claim_token = b"1234";
    let options = Options::default();
    let vote_pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
    let blinding_result = vote_pk.blind(rng, claim_token, true, &options)?;

    // SERVER validates some sort of proof and then signs the blinded message
    let sig = sk.blind_sign(rng, &blinding_result.blind_msg, &options)?;
    let token = BallotToken::new(sig);

    // 3. Voter unblinds the token into a signature
    // VOTER
    let opt = "Bob".to_string();
    let ballot = Ballot::from_token(token, opt, &blinding_result, claim_token, &options, &vote.pk).unwrap();
    
    // SERVER
    // validate blind signature
    let ballot_id = BallotID::new(&ballot);
    if let Ok(_) = Signature::from(ballot.sig).verify(&vote_pk, blinding_result.msg_randomizer, claim_token, &options) {
        println!("blind signature verified");
    } else {
        panic!("blind signature invalid");
    }
    let kt2_sig = secret.sign(&ballot_id.0);
    let stored_ballot = StoredBallot::new(ballot.opt, kt2_sig);
    
    println!("loading ballot");
    let maybe_ballot = read_maybe_ballot(&ballot_id, &db)?;
    if let Some(bytes) = maybe_ballot {
        let archived_ballot = unsafe { archived_root::<Ballot>(&bytes[..]) };
        println!("opt: {}", archived_ballot.opt);
    }

    Ok(())
}

static FLUSH_NOTIFY: LazyLock<Arc<Notify>> = LazyLock::new(|| Arc::new(Notify::const_new()));

struct Flusher {
    notify: Arc<Notify>,
}

impl Flusher {
    const fn new(notify: Arc<Notify>) -> Self {
        Flusher { notify }
    }

    fn run(&self, db: Db) {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            db.flush().unwrap();
            self.notify.notify_waiters();
        }
    }

    fn start(self, db: Db) {
        std::thread::spawn(move || self.run(db));
    }
}

#[derive(Debug)]
enum Error {
    SerializationError,
    IoError(io::Error),
    BlindRsaError(blind_rsa_signatures::Error),
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

#[derive(Clone, Copy)]
struct VoteID {
    hash: [u8; 32],
}

impl VoteID {
    fn new(vote: &Vote) -> Self {
        VoteID {
            hash: hash(&vote.pk).into(),
        }
    }
}

impl AsRef<[u8]> for VoteID {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

#[derive(Archive, Serialize, Deserialize)]
struct Vote {
    options: Vec<String>,
    pk: Vec<u8>,
}

async fn store_vote(vote: &Vote, db: &Db) -> Result<VoteID, Error> {
    let notify = FLUSH_NOTIFY.clone();
    let key = VoteID::new(&vote);
    let value = to_bytes::<_, 512>(vote).map_err(|_| Error::SerializationError)?;
    db.insert(key.clone(), value.as_slice())?;
    notify.notified().await;
    Ok(key)
}

impl Vote {
    fn new(options: Vec<String>) -> Result<(RsaSecretKey, Self), Error> {
        let KeyPair { pk, sk } = KeyPair::generate(&mut rand::thread_rng(), 2048)?;
        Ok((
            sk,
            Vote {
                options,
                pk: pk.to_public_key_der().unwrap().into_vec(),
            },
        ))
    }
}

#[derive(Archive, Serialize, Deserialize)]
struct BallotToken {
    blinded_sig: Vec<u8>,
}

impl BallotToken {
    fn new(sig: BlindSignature) -> Self {
        BallotToken { blinded_sig: sig.0 }
    }
}

#[derive(Archive, Serialize, Deserialize)]
struct StoredBallot {
    opt: String,
    vote_accepted_sig: [u8; SIGN_BYTES]
}

impl StoredBallot {
    fn new(opt: String, sig: kt2::Signature) -> Self {
        StoredBallot {
            opt,
            vote_accepted_sig: sig.0,
        }
    }
}

#[derive(Archive, Serialize, Deserialize)]
struct Ballot {
    vote_pk: Vec<u8>,
    opt: String,
    sig: Vec<u8>,
}

/// Stores a ballot in sled, wait for disk flush to complete asynchronously, and then returns the ballot ID
async fn store_ballot(ballot: &Ballot, db: &Db) -> Result<BallotID, Error> {
    let notify = FLUSH_NOTIFY.clone();
    let key = BallotID::new(&ballot);
    let value = to_bytes::<_, 512>(ballot).map_err(|_| Error::SerializationError)?;
    db.insert(key.clone(), value.as_slice())?;
    notify.notified().await;
    Ok(key)
}

fn read_maybe_ballot(id: &BallotID, db: &Db) -> Result<Option<InlineArray>, Error> {
    Ok(db.get(id.as_ref())?)
}

impl Ballot {
    fn from_token(
        token: BallotToken,
        opt: String,
        blinding_result: &BlindingResult,
        claim_token: &[u8],
        options: &Options,
        vote_pk: &[u8],
    ) -> Result<Self, Error> {
        let pk =
            RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(vote_pk).unwrap());

        let sig = pk.finalize(
            &token.blinded_sig.into(),
            &blinding_result.secret,
            blinding_result.msg_randomizer,
            &claim_token,
            &options,
        )?;

        Ok(Ballot {
            vote_pk: vote_pk.into(),
            opt,
            sig: sig.into(),
        })
    }
}

#[derive(Clone, Copy)]
struct BallotID([u8; 32]);

impl AsRef<[u8]> for BallotID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BallotID {
    fn new(vote: &Ballot) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(vote.opt.as_bytes());
        hasher.update(&vote.sig);
        BallotID(*hasher.finalize().as_bytes())
    }
}
