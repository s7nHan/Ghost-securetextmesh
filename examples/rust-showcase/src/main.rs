mod lifecycle;
mod model;

use tokio::sync::mpsc;

use lifecycle::simulate_three_node_lifecycle;
use model::{PublicAlgorithmSuite, PublicMessage};

#[tokio::main]
async fn main() {
    let suite = PublicAlgorithmSuite::default();

    println!("GHOST public Rust lifecycle showcase");
    println!("------------------------------------");
    println!("Runtime/orchestration: Tokio");
    println!("Signature: {}", suite.signature);
    println!("Key establishment: {}", suite.key_establishment);
    println!("Authenticated encryption: {}", suite.authenticated_encryption);
    println!("Threshold secret sharing: {}", suite.threshold_secret_sharing);
    println!();
    println!("NOTE: this is a non-production public model; it performs no cryptography.");
    println!();

    let message = PublicMessage::new(
        1,
        "Public showcase payload — no production protocol material.",
        3,
    );

    println!(
        "Message {}: {} bytes, {} public-model fragments",
        message.id,
        message.body.len(),
        message.fragments
    );
    println!();

    let (tx, mut rx) = mpsc::channel(32);
    let worker = tokio::spawn(simulate_three_node_lifecycle(message, tx));

    while let Some(event) = rx.recv().await {
        println!(
            "[{} | {}] message={} stage={} — {}",
            event.node,
            event.role,
            event.message_id,
            event.stage,
            event.note
        );
    }

    if let Err(join_error) = worker.await {
        eprintln!("public showcase task failed: {join_error}");
        std::process::exit(1);
    }

    println!();
    println!("Public lifecycle showcase complete.");
}
