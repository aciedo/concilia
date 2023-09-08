use std::fmt::{Display, Formatter, self};

use blake3::hash;
use blind_rsa_signatures::{KeyPair, SecretKey as RsaSecretKey, reexports::rsa::pkcs8::EncodePublicKey};
use hashbrown::HashMap;
use rkyv::{Archive, Serialize, Deserialize};
use serde::{Serialize as Ser, Deserialize as De, Deserializer, de::{Visitor, MapAccess}, Serializer, ser::SerializeStruct};

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

#[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[archive(check_bytes)]
pub struct Vote {
    pub title: String,
    pub desc: String,
    pub opts: HashMap<String, u64>,
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

impl serde::Serialize for Vote {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Vote", 4)?;
        state.serialize_field("title", &self.title)?;
        state.serialize_field("desc", &self.desc)?;
        state.serialize_field("opts", &self.opts)?;
        state.serialize_field("pk", &bs58::encode(&self.pk).into_string())?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for Vote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(De)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Title, Desc, Opts, Pk }

        struct VoteVisitor;

        impl<'de> Visitor<'de> for VoteVisitor {
            type Value = Vote;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Vote")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Vote, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut title = None;
                let mut desc = None;
                let mut opts = None;
                let mut pk = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Title => title = Some(map.next_value()?),
                        Field::Desc => desc = Some(map.next_value()?),
                        Field::Opts => opts = Some(map.next_value()?),
                        Field::Pk => pk = Some(bs58::decode(map.next_value::<String>()?).into_vec().map_err(serde::de::Error::custom)?),
                    }
                }
                let title = title.ok_or_else(|| serde::de::Error::missing_field("title"))?;
                let desc = desc.ok_or_else(|| serde::de::Error::missing_field("desc"))?;
                let opts = opts.ok_or_else(|| serde::de::Error::missing_field("opts"))?;
                let pk = pk.ok_or_else(|| serde::de::Error::missing_field("pk"))?;
                Ok(Vote { title, desc, opts, pk })
            }
        }

        deserializer.deserialize_struct("Vote", &["title", "desc", "opts", "pk"], VoteVisitor)
    }
}