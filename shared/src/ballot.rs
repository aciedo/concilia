use std::{fmt::{Formatter, Display, self}, ops::Deref};

use blake3::Hasher;
use blind_rsa_signatures::{BlindSignature, BlindingResult, Options, PublicKey as RsaPublicKey};
use rkyv::{Archive, Serialize, Deserialize};
use serde::{Serialize as Ser, Deserialize as De, de::{Visitor, self}};

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

#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub enum BallotSig {
    D3(Vec<u8>),
    Blind(Vec<u8>),
}

impl Ser for BallotSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (variant_byte, bytes) = match self {
            BallotSig::D3(bytes) => (0u8, bytes),
            BallotSig::Blind(bytes) => (1u8, bytes),
        };
        let mut vec = Vec::with_capacity(1usize + bytes.len());
        vec.push(variant_byte);
        vec.extend_from_slice(bytes);
        let str = bs58::encode(&vec).into_string();
        serializer.serialize_str(&str)
    }
}

impl<'de> De<'de> for BallotSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BallotSigVisitor;
        
        impl<'de> Visitor<'de> for BallotSigVisitor {
            type Value = BallotSig;
        
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a base58 encoded string representing BallotSig")
            }
        
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let vec = bs58::decode(v).into_vec().map_err(E::custom)?;
        
                let (variant_byte, bytes) = vec.split_at(1);
                match variant_byte {
                    [0u8] => Ok(BallotSig::D3(bytes.to_vec())),
                    [1u8] => Ok(BallotSig::Blind(bytes.to_vec())),
                    _ => Err(E::custom("Invalid variant byte")),
                }
            }
        }
        
        deserializer.deserialize_str(BallotSigVisitor)
    }
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
        claim_token: &[u8],
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
        let mut hasher = Hasher::new();
        hasher.update(vote.opt.as_bytes());
        hasher.update(&vote.sig);
        BallotID(*hasher.finalize().as_bytes())
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
