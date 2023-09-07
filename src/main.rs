#![feature(lazy_cell)]
use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use blake3::hash;
use kt2::Keypair;
use shared::Error;
use sled::Db;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

mod client;
mod db;
mod handlers;
mod shared;

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

    let Keypair { secret, public } = Keypair::generate(None);
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
        Flusher::new(FLUSH_NOTIFY.clone()).start(db.clone());
        loop {
            if let Some(sender) = db_rx.recv().await {
                let _ = sender.send(db.clone());
            }
        }
    });

    let secret = Arc::new(secret);
    let db_getter = DbGetter(db_tx);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_getter.clone()))
            .app_data(web::Data::new(secret.clone()))
            .service(create_vote)
            .service(verify_eligibility)
            .service(submit_ballot)
            .service(get_votes)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
    .map_err(|e| e.into())
}
