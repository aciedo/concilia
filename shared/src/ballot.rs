use std::{fmt::{Formatter, Display}, ops::Deref};

use blake3::hash;
use blind_rsa_signatures::{BlindSignature, BlindingResult, Options, PublicKey as RsaPublicKey};
use rkyv::{Archive, Serialize, Deserialize};
use serde::{Serialize as Ser, Deserialize as De};

use crate::{StringConversion, error::Error};

#[derive(Archive, Serialize, Deserialize, Ser, De)]
#[archive(check_bytes)]
pub struct BallotToken {
    pub blinded_sig: Vec<u8>,
}

impl StringConversion for BallotToken {
    fn as_string(&self) -> String {
        bs58::encode(&self.blinded_sig).into_string()
    }
    
    fn from_string(s: String) -> Option<Self>
    where
        Self: Sized {
            bs58::decode(&s).into_vec().ok().map(|blinded_sig| BallotToken { blinded_sig })
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

#[derive(Archive, Serialize, Deserialize, Debug, Ser, De)]
#[archive(check_bytes)]
pub enum BallotSig {
    D3(#[serde(with = "serde_bytes")] Vec<u8>),
    Blind(#[serde(with = "serde_bytes")] Vec<u8>),
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
    pub opt: String,
    pub sig: BallotSig,
}

impl Ballot {
    pub fn from_token(
        token: BallotToken,
        opt: String,
        blinding_result: &BlindingResult,
        claim_token: &[u8; 32],
        options: &Options,
        pk: &RsaPublicKey,
    ) -> Result<Self, Error> {
        let sig = pk.finalize(
            &token.blinded_sig.into(),
            &blinding_result.secret,
            blinding_result.msg_randomizer,
            &claim_token,
            &options,
        )?;

        Ok(Ballot {
            opt,
            sig: BallotSig::Blind(sig.into()),
        })
    }
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
        BallotID(*hash(&[vote.opt.as_bytes(), &vote.sig].concat()).as_bytes())
    }
}

impl StringConversion for BallotID {
    fn as_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
    fn from_string(s: String) -> Option<Self> {
        let hash = bs58::decode(&s).into_vec().ok()?;
        if hash.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Some(BallotID(arr))
    }
}

impl Display for BallotID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[derive(Archive, Serialize, Deserialize, Ser, De)]
pub struct BallotSubmissionResponse {
    #[serde(with = "serde_bytes")]
    pub kt2_sig: Vec<u8>,
    pub ballot_id: BallotID,
}