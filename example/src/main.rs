use tracing::info;
use concilia::Client;
use concilia_shared::{StringConversion, VoteID};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let client = Client::new("http://localhost:8080");
    // try get vote_id from first argument
    let arg = std::env::args().nth(1);
    let vote_id = match arg {
        Some(arg) => VoteID::from_string(arg).unwrap(),
        None => client.create_vote("test vote", "", ["a", "b", "c"])
            .await
            .unwrap(),
    };
    info!("vote_id: {}", vote_id);
    let vote = client.get_vote(&vote_id).await.unwrap();

    let mut handles = vec![];
    for i in 0..50 {
        let vote = vote.clone();
        let client = Client::new("http://localhost:8080");
        let handle = tokio::spawn(async move {
            let opt = match i % 3 {
                0 => "a",
                1 => "b",
                2 => "c",
                _ => unreachable!(),
            };
            for _ in 0..10 {
                client.submit_ballot(&vote, opt.to_string()).await.unwrap();
            }
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let vote = client.get_vote(&vote_id).await.unwrap();
    info!("{}", vote);
}
