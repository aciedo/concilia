use std::sync::{LazyLock, Arc};

use blind_rsa_signatures::SecretKey as RsaSecretKey;
use rkyv::{from_bytes, to_bytes};
use sled::{Db, InlineArray};
use tokio::{task::spawn_blocking, sync::Notify};
use tracing::trace;

use concilia_shared::{VoteID, Ballot, Error, Vote, BallotID};

use crate::cuckoo::CuckooFilter;

pub fn store_filter(filter: &CuckooFilter, index: usize, db: &Db) -> Result<(), Error> {
    let value = to_bytes::<_, 1024>(filter).map_err(|_| Error::SerializationError)?;
    trace!("updating cuckoo_filter_{} with size {}", index, value.len());
    db.insert([b"cuckoo_filter_".as_ref(), &index.to_be_bytes()].concat(), value.as_ref())?;
    Ok(())
}

pub fn store_vote_sk(sk: &RsaSecretKey, vote_id: &VoteID, db: &Db) -> Result<(), Error> {
    let sk = sk.to_der().unwrap();
    let key = [b"sk_vote_", vote_id.as_ref()].concat();
    trace!("storing vote sk, size {}", sk.len());
    db.insert(key, sk)?;
    Ok(())
}

pub async fn maybe_read_vote_sk(vote_id: &VoteID, db: Db) -> Result<Option<RsaSecretKey>, Error> {
    let key = [b"sk_vote_", vote_id.as_ref()].concat();
    spawn_blocking(move || {
        let sk = db
            .get(key)?
            .map(|bytes| RsaSecretKey::from_der(&bytes).unwrap());
        Ok(sk)
    })
    .await?
}

pub fn store_vote(vote: &Vote, db: &Db) -> Result<VoteID, Error> {
    let vote_id = VoteID::new(vote);
    let key = [b"vote_", vote_id.as_ref()].concat();
    let value = to_bytes::<_, 512>(vote).map_err(|_| Error::SerializationError)?;
    trace!("storing vote {}, size {}", &vote_id, value.len());
    db.insert(key, value.as_ref())?;
    Ok(vote_id)
}

pub async fn maybe_read_vote(vote_id: &VoteID, db: Db) -> Result<Option<InlineArray>, Error> {
    let key = [b"vote_", vote_id.as_ref()].concat();
    spawn_blocking(move || Ok(db.get(key)?)).await?
}

pub fn store_ballot(ballot: &Ballot, ballot_id: &BallotID, vote_id: &VoteID, db: &Db) -> Result<(), Error> {
    let key = [vote_id.hash.as_ref(), b"_ballot_", ballot_id.as_ref()].concat();
    let value = to_bytes::<_, 512>(ballot).map_err(|_| Error::SerializationError)?;
    trace!("storing ballot {}, size {}", &ballot_id, value.len());
    db.insert(key, value.as_ref())?;
    Ok(())
}

pub async fn maybe_read_ballot(
    vote_id: &VoteID,
    ballot_id: &BallotID,
    db: Db,
) -> Result<Option<InlineArray>, Error> {
    let key = [vote_id.hash.as_ref(), b"_ballot_", ballot_id.as_ref()].concat();
    spawn_blocking(move || Ok(db.get(key)?)).await?
}

pub fn apply_ballot(vote_id: &VoteID, ballot: &Ballot, db: Db) -> Result<(), Error> {
    let key = [b"vote_", vote_id.as_ref()].concat();
    trace!("applying ballot to {}", &vote_id);
    db.update_and_fetch(key, |old| match old {
        Some(old) => {
            let mut vote = from_bytes::<Vote>(old).unwrap();
            *vote.opts.get_mut(&ballot.opt)? += 1;
            Some(to_bytes::<_, 512>(&vote).unwrap().into_vec())
        }
        None => None,
    })?;
    Ok(())
}

/// The CHECKPOINT notification is sent out after every successful disk flush
pub static CHECKPOINT: LazyLock<Arc<Notify>> = LazyLock::new(|| Arc::new(Notify::const_new()));

/// A background task that flushes to disk every 50ms
pub struct Flusher {
    notify: Arc<Notify>,
}

impl Flusher {
    pub const fn new(notify: Arc<Notify>) -> Self {
        Flusher { notify }
    }

    pub fn run(&self, db: Db) {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            db.flush().unwrap();
            self.notify.notify_waiters();
        }
    }

    pub fn start(self, db: Db) {
        std::thread::spawn(move || self.run(db));
    }
}
