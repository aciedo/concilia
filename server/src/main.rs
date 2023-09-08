#![feature(lazy_cell)]
#![feature(iter_advance_by)]
use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use blake3::hash;
use concilia_shared::Error;
use kt2::Keypair;
use sled::Db;
use tokio::sync::{
    mpsc::{self, error::TryRecvError},
    oneshot,
};
use tracing::info;

mod db;
mod handlers;

use db::*;

use handlers::*;

// 1. Create vote
// 2. Voter authenticates themselves to receive a blinded signature signed by vote's secret key
// 3. Voter unblinds signature
// 4. Voter submits vote and unblinded signature
// 5. Server signs the ballot using KT2-D3, replacing the blind sig with a regular sig (a lot smaller)
// 6. Server stores the ballot in the database
// 7. HTTP call awaits fsync to ensure the ballot is stored on disk
// 8. Server returns the ballot ID to the voter

#[derive(Clone)]
struct DbGetter(mpsc::UnboundedSender<oneshot::Sender<Db>>);

impl DbGetter {
    async fn get(&self) -> Db {
        let (tx, rx) = oneshot::channel();
        self.0.send(tx).unwrap();
        rx.await.unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let seed_bytes;
    let seed = if let Some(seed) = std::env::var("SEED").ok() {
        seed_bytes = bs58::decode(seed)
            .into_vec()
            .map_err(|_| Error::SerializationError)?;
        Some(seed_bytes.as_slice())
    } else {
        None
    };
    let Keypair { secret, public } = Keypair::generate(seed);
    info!(
        "Server D3 public key fingerprint {}",
        bs58::encode(hash(&public.bytes).as_bytes()).into_string()
    );
    let (db_tx, mut db_rx) = mpsc::unbounded_channel::<oneshot::Sender<Db>>();
    tokio::spawn(async move {
        // `Db` is `Send + !Sync`, so this thread hands out `Db` instances to other threads
        let db = sled::Config::default()
            .flush_every_ms(None)
            .path("concilia.db")
            .open()
            .unwrap();
        Flusher::new(CHECKPOINT.clone()).start(db.clone());
        let mut pool_cache = Vec::with_capacity(100);
        let mut available = 0;

        fn replenish(pool_cache: &mut Vec<Db>, available: &mut usize, db: &Db) {
            let additional = 100 - *available;
            for _ in 0..additional {
                pool_cache.push(db.clone());
            }
            *available += additional;
        }

        replenish(&mut pool_cache, &mut available, &db);
        loop {
            match db_rx.try_recv() {
                Ok(sender) => {
                    let db = match pool_cache.pop() {
                        Some(db) => db,
                        None => {
                            replenish(&mut pool_cache, &mut available, &db);
                            pool_cache.pop().unwrap()
                        }
                    };
                    available -= 1;
                    sender.send(db).unwrap();
                }
                Err(TryRecvError::Empty) => replenish(&mut pool_cache, &mut available, &db),
                Err(TryRecvError::Disconnected) => break,
            }
        }
    });
    let secret = Arc::new(secret);
    let public = Arc::new(public);
    let db_getter = DbGetter(db_tx);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_getter.clone()))
            .app_data(web::Data::new(secret.clone()))
            .app_data(web::Data::new(public.clone()))
            .service(kt2_public)
            .service(create_vote)
            .service(verify_eligibility)
            .service(submit_ballot)
            .service(get_votes)
            .service(get_vote)
            .service(get_ballot)
            .service(get_ballots)
        // .wrap_fn(|req, srv| {
        //     let start = std::time::Instant::now();
        //     srv.call(req).map(move |res| {
        //         if let Ok(res) = res.as_ref() {
        //             info!(
        //                 "{} {:?}",
        //                 res.status(),
        //                 start.elapsed()
        //             );
        //         }
        //         res
        //     })
        // })
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
    .map_err(|e| e.into())
}
