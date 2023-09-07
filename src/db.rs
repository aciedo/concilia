use std::sync::{LazyLock, Arc};

use blind_rsa_signatures::SecretKey as RsaSecretKey;
use rkyv::{from_bytes, to_bytes};
use sled::{Db, InlineArray};
use tokio::{task::spawn_blocking, sync::Notify};
use tracing::debug;

use crate::shared::{VoteID, Ballot, Error, Vote, BallotID};

pub fn store_vote_sk(sk: &RsaSecretKey, vote_id: &VoteID, db: &Db) -> Result<(), Error> {
    let sk = sk.to_der().unwrap();
    let key = [b"sk_vote_", vote_id.as_ref()].concat();
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
    db.insert(key, value.as_ref())?;
    Ok(vote_id)
}

pub async fn maybe_read_vote(vote_id: &VoteID, db: Db) -> Result<Option<InlineArray>, Error> {
    let key = [b"vote_", vote_id.as_ref()].concat();
    spawn_blocking(move || Ok(db.get(key)?)).await?
}

pub fn store_ballot(ballot: &Ballot, ballot_id: &BallotID, db: &Db) -> Result<(), Error> {
    let key = [b"ballot_", ballot_id.as_ref()].concat();
    let value = to_bytes::<_, 512>(ballot).map_err(|_| Error::SerializationError)?;
    debug!("storing ballot {}", &ballot_id);
    db.insert(key, value.as_ref())?;
    Ok(())
}

pub fn apply_ballot(vote_id: &VoteID, ballot: &Ballot, db: Db) -> Result<(), Error> {
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

pub static FLUSH_NOTIFY: LazyLock<Arc<Notify>> = LazyLock::new(|| Arc::new(Notify::const_new()));

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