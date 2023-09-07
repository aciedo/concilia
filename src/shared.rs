use std::{io, fmt::{Display, Formatter}, ops::Deref};

use blake3::{hash, Hasher};
use blind_rsa_signatures::{SecretKey as RsaSecretKey, KeyPair, BlindSignature, reexports::rsa::pkcs8::EncodePublicKey};
use hashbrown::HashMap;
use rkyv::{Archive, Serialize, Deserialize};
use serde::{Serialize as Ser, Deserialize as De};
use tokio::task::JoinError;

#[derive(Debug)]
pub enum Error {
    SerializationError,
    IoError(io::Error),
    BlindRsaError(blind_rsa_signatures::Error),
    VoteNotFound,
    TaskError,
    BallotWrongSigType { expected: BallotSig, got: BallotSig },
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

pub trait AsString {
    fn as_string(&self) -> String;
}

#[derive(Clone, Copy, Archive, Serialize, Deserialize, Ser, De, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct VoteID {
    pub hash: [u8; 32],
}

impl VoteID {
    pub fn new(vote: &Vote) -> Self {
        VoteID {
            hash: hash(&vote.pk).into(),
        }
    }
}

impl AsString for VoteID {
    fn as_string(&self) -> String {
        bs58::encode(&self.hash).into_string()
    }
}

impl Display for VoteID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl AsRef<[u8]> for VoteID {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

#[derive(Archive, Serialize, Deserialize, Ser, De, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct Vote {
    pub options: HashMap<String, u64>,
    pub pk: Vec<u8>,
}

impl Vote {
    pub fn new(options: Vec<String>) -> Result<(RsaSecretKey, Self), Error> {
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

#[derive(Archive, Serialize, Deserialize, Ser, De)]
#[archive(check_bytes)]
pub struct BallotToken {
    pub blinded_sig: Vec<u8>,
}

impl AsString for BallotToken {
    fn as_string(&self) -> String {
        bs58::encode(&self.blinded_sig).into_string()
    }
}

impl BallotToken {
    pub fn new(sig: BlindSignature) -> Self {
        BallotToken { blinded_sig: sig.0 }
    }
}

impl Display for BallotToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[derive(Archive, Serialize, Deserialize, Ser, De, Debug)]
#[archive(check_bytes)]
pub enum BallotSig {
    D3(Vec<u8>),
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

#[derive(Archive, Serialize, Deserialize, Ser, De)]
#[archive(check_bytes)]
pub struct Ballot {
    pub vote_id: VoteID,
    pub opt: String,
    pub sig: BallotSig,
}

#[derive(Clone, Copy, Archive, Serialize, Deserialize, Ser, De)]
#[archive(check_bytes)]
pub struct BallotID(pub [u8; 32]);

impl AsRef<[u8]> for BallotID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BallotID {
    pub fn new(vote: &Ballot) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(vote.opt.as_bytes());
        hasher.update(&vote.sig);
        BallotID(*hasher.finalize().as_bytes())
    }
}

impl AsString for BallotID {
    fn as_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl Display for BallotID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}
