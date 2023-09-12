use std::fmt::{Display, Formatter};

use blake3::hash;
use blind_rsa_signatures::{KeyPair, SecretKey as RsaSecretKey, reexports::rsa::pkcs8::EncodePublicKey};
use hashbrown::HashMap;
use rkyv::{Archive, Serialize, Deserialize};
use serde::{Serialize as Ser, Deserialize as De};

use crate::{StringConversion, error::Error};

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

impl StringConversion for VoteID {
    fn as_string(&self) -> String {
        bs58::encode(&self.hash).into_string()
    }
    
    fn from_string(s: String) -> Option<Self>
    where
        Self: Sized {
            bs58::decode(&s).into_vec().ok().map(|hash| VoteID { hash: hash.try_into().unwrap() })
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

#[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Clone, Ser, De)]
#[archive(check_bytes)]
pub struct Vote {
    pub title: String,
    pub desc: String,
    pub opts: HashMap<String, u64>,
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
}

impl Vote {
    pub fn new(title: String, desc: String, opts: Vec<String>) -> Result<(RsaSecretKey, Self), Error> {
        let KeyPair { pk, sk } = KeyPair::generate(&mut rand::thread_rng(), 2048)?;
        Ok((
            sk,
            Vote {
                title,
                desc,
                opts: opts.into_iter().map(|opt| (opt, 0)).collect(),
                pk: pk.to_public_key_der().unwrap().into_vec(),
            },
        ))
    }
}

impl Display for Vote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vote {{ title: {:?}, description: {:?}, options: {:?}, pk: {} }}", self.title, self.desc, self.opts, bs58::encode(&self.pk).into_string())
    }
}
