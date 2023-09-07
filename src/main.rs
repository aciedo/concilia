#![feature(lazy_cell)]
use std::{
    io,
    sync::{Arc, LazyLock}, ops::Deref, fmt::{Display, Formatter},
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
use hashbrown::HashMap;
use kt2::{Keypair, SIGN_BYTES};
use rkyv::{archived_root, from_bytes, to_bytes, Archive, Deserialize, Serialize};
use sled::{Db, InlineArray};
use tokio::{
    sync::Notify,
    task::{spawn_blocking, JoinError},
};
use tracing::{debug, info};

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
    tracing_subscriber::fmt::init();
    let db = sled::Config::default()
        .flush_every_ms(None)
        .path("concilia.db")
        .open()?;
    let rng = &mut rand::thread_rng();
    Flusher::new(FLUSH_NOTIFY.clone()).start(db.clone());
    let flush_notification = FLUSH_NOTIFY.clone();

    let Keypair { secret, public } = Keypair::generate(None);
    let options = Options::default();

    // 1. Create vote on SERVER
    let (sk, vote) = Vote::new(vec!["Bob".to_string()]).unwrap();
    let vote_id = store_vote(&vote, &db)?;
    store_vote_sk(&sk, &vote_id, &db)?;
    flush_notification.notified().await;
    info!("SERVER vote created: {}", &vote_id);

    // 2. VOTER authenticates themselves to receive a blinded signature signed by vote's secret key
    // This would usually include some sort of ID check
    let vote_id = VoteID::new(&vote);
    let claim_token = b"1234";
    let vote_pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
    let blinding_result = vote_pk.blind(rng, claim_token, true, &options)?;
    let blind_msg = blinding_result.blind_msg.clone();
    info!("VOTER created blind msg: {}", bs58::encode(&blind_msg).into_string());
    // blind_msg -> SERVER

    // SERVER validates some sort of proof and then signs the blinded message
    // SERVER CANNOT see claim_token when signing it
    info!("SERVER loading vote blinding secret key");
    let sk = maybe_read_vote_sk(&vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
    let sig = sk.blind_sign(rng, &blind_msg, &options)?;
    let token = BallotToken::new(sig);
    info!("SERVER issued ballot token: {}", bs58::encode(&token.blinded_sig).into_string());
    // token -> VOTER

    // 3. Voter unblinds the token into a signature
    // VOTER
    info!("VOTER unblinding ballot token");
    let opt = "Bob".to_string();
    let mut ballot = Ballot::from_token(
        token,
        opt,
        &blinding_result,
        claim_token,
        &options,
        &vote_pk,
        &vote_id,
    )
    .unwrap();
    info!("VOTER created ballot");
    // ballot -> SERVER

    // SERVER
    // validate blind signature
    let vote_bytes = maybe_read_vote(&vote_id, db.clone())
        .await?
        .ok_or(Error::VoteNotFound)?;
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
        blinding_result.msg_randomizer,
        claim_token,
        &options,
    )?;
    info!("SERVER blind signature valid");

    // this is your "vote counted" receipt
    // we replace the blind sig with a D3 sig because PQ blind sigs are huge (22kb each) so we don't bother storing them
    let kt2_sig = secret.sign(&ballot_id.0);
    ballot.sig = BallotSig::D3(kt2_sig.0);
    store_ballot(&ballot, &ballot_id, &db)?;
    apply_ballot(&vote_id, &ballot, db.clone())?;
    flush_notification.notified().await;
    // (ballot_id, kt2_sig) -> VOTER
    info!("SERVER counted ballot");

    info!("VOTER ballot id {}", ballot_id);
    info!("VOTER validating vote receipt");
    if public.verify(ballot_id.as_ref(), &kt2_sig) {
        info!("VOTER vote receipt valid");
    } else {
        info!("VOTER vote receipt invalid");
    }

    Ok(())
}

fn apply_ballot(vote_id: &VoteID, ballot: &Ballot, db: Db) -> Result<(), Error> {
    let key = [b"vote_", vote_id.as_ref()].concat();
    debug!("applying ballot to {}", &vote_id);
    db.update_and_fetch(key, |old| match old {
        Some(old) => {
            let mut vote = from_bytes::<Vote>(old).unwrap();
            *vote.options.get_mut(&ballot.opt)? += 1;
            Some(to_bytes::<_, 512>(&vote).unwrap().into_vec())
        }
        None => None,
    })?;
    Ok(())
}

fn store_vote_sk(sk: &RsaSecretKey, vote_id: &VoteID, db: &Db) -> Result<(), Error> {
    let sk = sk.to_der().unwrap();
    let key = [b"sk_vote_", vote_id.as_ref()].concat();
    db.insert(key, sk)?;
    Ok(())
}

async fn maybe_read_vote_sk(vote_id: &VoteID, db: Db) -> Result<Option<RsaSecretKey>, Error> {
    let key = [b"sk_vote_", vote_id.as_ref()].concat();
    spawn_blocking(move || {
        let sk = db
            .get(key)?
            .map(|bytes| RsaSecretKey::from_der(&bytes).unwrap());
        Ok(sk)
    })
    .await?
}

fn store_vote(vote: &Vote, db: &Db) -> Result<VoteID, Error> {
    let vote_id = VoteID::new(vote);
    let key = [b"vote_", vote_id.as_ref()].concat();
    let value = to_bytes::<_, 512>(vote).map_err(|_| Error::SerializationError)?;
    db.insert(key, value.as_ref())?;
    Ok(vote_id)
}

async fn maybe_read_vote(vote_id: &VoteID, db: Db) -> Result<Option<InlineArray>, Error> {
    let key = [b"vote_", vote_id.as_ref()].concat();
    spawn_blocking(move || Ok(db.get(key)?)).await?
}

fn store_ballot(ballot: &Ballot, ballot_id: &BallotID, db: &Db) -> Result<(), Error> {
    let key = [b"ballot_", ballot_id.as_ref()].concat();
    let value = to_bytes::<_, 512>(ballot).map_err(|_| Error::SerializationError)?;
    debug!("storing ballot {}", &ballot_id);
    db.insert(key, value.as_ref())?;
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
    VoteNotFound,
    TaskError(JoinError),
    BallotWrongSigType {
        expected: BallotSig,
        got: BallotSig,
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
    fn from(e: JoinError) -> Self {
        Error::TaskError(e)
    }
}

#[derive(Clone, Copy, Archive, Serialize, Deserialize, PartialEq, Eq)]
#[archive(check_bytes)]
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

impl Display for VoteID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.hash).into_string())
    }
}

impl AsRef<[u8]> for VoteID {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

#[derive(Archive, Serialize, Deserialize, PartialEq, Eq)]
#[archive(check_bytes)]
struct Vote {
    options: HashMap<String, u64>,
    pk: Vec<u8>,
}

impl Vote {
    fn new(options: Vec<String>) -> Result<(RsaSecretKey, Self), Error> {
        let KeyPair { pk, sk } = KeyPair::generate(&mut rand::thread_rng(), 2048)?;
        Ok((
            sk,
            Vote {
                options: options.into_iter().map(|opt| (opt, 0)).collect(),
                pk: pk.to_public_key_der().unwrap().into_vec(),
            },
        ))
    }
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
struct BallotToken {
    blinded_sig: Vec<u8>,
}

impl BallotToken {
    fn new(sig: BlindSignature) -> Self {
        BallotToken { blinded_sig: sig.0 }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
enum BallotSig {
    D3([u8; SIGN_BYTES]),
    Blind(Vec<u8>),
}

impl Deref for BallotSig {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            BallotSig::D3(sig) => sig,
            BallotSig::Blind(sig) => sig,
        }
    }
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
struct Ballot {
    vote_id: VoteID,
    opt: String,
    sig: BallotSig,
}

impl Ballot {
    fn from_token(
        token: BallotToken,
        opt: String,
        blinding_result: &BlindingResult,
        claim_token: &[u8],
        options: &Options,
        pk: &RsaPublicKey,
        vote_id: &VoteID,
    ) -> Result<Self, Error> {
        let sig = pk.finalize(
            &token.blinded_sig.into(),
            &blinding_result.secret,
            blinding_result.msg_randomizer,
            &claim_token,
            &options,
        )?;

        Ok(Ballot {
            vote_id: vote_id.clone(),
            opt,
            sig: BallotSig::Blind(sig.into()),
        })
    }
}

#[derive(Clone, Copy, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
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

impl Display for BallotID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}
