use anyhow::{bail, ensure, Context, Result};
use futures::StreamExt;
use ghost_public_crypto::{
    primitives::{generate_mldsa87, generate_mlkem768, MlKemKeys},
    sealed_message::{open_message, seal_message},
    wire::{decode_authenticated_wire, encode_wire},
};
use libp2p::{gossipsub, identity, swarm::SwarmEvent, Swarm, SwarmBuilder};
use std::time::Duration;

const TOPIC: &str = "ghost-public-independent-mesh-test-v1";
const PLAINTEXT: &[u8] = b"GHOST REAL THREE NODE INDEPENDENT QUIC MESSAGE";

fn new_node(
    identity: identity::Keypair,
    topic: &gossipsub::IdentTopic,
) -> Swarm<gossipsub::Behaviour> {
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(350))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(64 * 1024)
                .build()
                .expect("valid Gossipsub config");

            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)
                .expect("signed Gossipsub behaviour")
        })
        .expect("network behaviour")
        .build();

    swarm
        .behaviour_mut()
        .subscribe(topic)
        .expect("topic subscription");

    swarm
}

fn decrypt_for_receiver(
    packet: &[u8],
    sender_public: &[u8],
    receivers: &[MlKemKeys; 5],
) -> Result<()> {
    let authenticated =
        decode_authenticated_wire(packet, sender_public).map_err(anyhow::Error::msg)?;

    let plaintext = open_message(
        &authenticated,
        sender_public,
        [
            (0, receivers[0].secret.as_slice()),
            (2, receivers[2].secret.as_slice()),
            (4, receivers[4].secret.as_slice()),
        ],
    )
    .map_err(anyhow::Error::msg)?;

    ensure!(
        plaintext.as_slice() == PLAINTEXT,
        "receiver plaintext mismatch"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_independent_public_message_through_three_quic_nodes() -> Result<()> {
    let signing = generate_mldsa87();

    let receivers: [MlKemKeys; 5] = std::array::from_fn(|_| generate_mlkem768());

    let public_keys: [Vec<u8>; 5] = std::array::from_fn(|i| receivers[i].public.clone());

    let sealed = seal_message(PLAINTEXT, &signing.public, &signing.secret, &public_keys)
        .map_err(anyhow::Error::msg)?;

    let packet = encode_wire(&sealed).map_err(anyhow::Error::msg)?;

    ensure!(
        packet.len() <= 64 * 1024,
        "message exceeds transport frame limit"
    );

    let identity_a = identity::Keypair::generate_ed25519();
    let identity_b = identity::Keypair::generate_ed25519();
    let identity_c = identity::Keypair::generate_ed25519();

    let id_a = identity_a.public().to_peer_id();
    let id_b = identity_b.public().to_peer_id();
    let id_c = identity_c.public().to_peer_id();

    ensure!(id_a != id_b && id_b != id_c && id_a != id_c);

    let topic = gossipsub::IdentTopic::new(TOPIC);
    let topic_hash = topic.hash();

    let mut a = new_node(identity_a, &topic);
    let mut b = new_node(identity_b, &topic);
    let mut c = new_node(identity_c, &topic);

    b.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;

    let address_b = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = b.select_next_some().await {
                break address;
            }
        }
    })
    .await
    .context("relay did not listen on QUIC")?;

    println!("REAL QUIC RELAY: {address_b}");

    // Deliberately establish only A-B and C-B links.
    // There is no direct A-C connection.
    a.dial(address_b.clone())?;
    c.dial(address_b)?;

    let mut b_sees_a = false;
    let mut b_sees_c = false;
    let mut a_sees_b = false;
    let mut c_sees_b = false;

    let mut ready_at: Option<tokio::time::Instant> = None;
    let mut published = false;
    let mut relay_received = false;

    let mut ticker = tokio::time::interval(Duration::from_millis(150));

    let execution = async {
        loop {
            tokio::select! {
                event = a.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        gossipsub::Event::Subscribed {
                            peer_id,
                            topic: subscribed,
                        }
                    ) = event {
                        if peer_id == id_b && subscribed == topic_hash {
                            a_sees_b = true;
                        }
                    }
                }

                event = b.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(
                            gossipsub::Event::Subscribed {
                                peer_id,
                                topic: subscribed,
                            }
                        ) if subscribed == topic_hash => {
                            if peer_id == id_a {
                                b_sees_a = true;
                            }
                            if peer_id == id_c {
                                b_sees_c = true;
                            }
                        }

                        SwarmEvent::Behaviour(
                            gossipsub::Event::Message {
                                message,
                                ..
                            }
                        ) => {
                            ensure!(
                                message.source == Some(id_a),
                                "relay received an unexpected sender"
                            );

                            decode_authenticated_wire(
                                &message.data,
                                &signing.public,
                            )
                            .map_err(anyhow::Error::msg)?;

                            relay_received = true;

                            println!(
                                "QUIC RELAY B: AUTHENTIC MESSAGE RECEIVED"
                            );
                        }

                        _ => {}
                    }
                }

                event = c.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(
                            gossipsub::Event::Subscribed {
                                peer_id,
                                topic: subscribed,
                            }
                        ) if peer_id == id_b
                            && subscribed == topic_hash => {
                            c_sees_b = true;
                        }

                        SwarmEvent::Behaviour(
                            gossipsub::Event::Message {
                                message,
                                ..
                            }
                        ) => {
                            ensure!(
                                message.source == Some(id_a),
                                "receiver detected wrong original Peer ID"
                            );

                            ensure!(
                                relay_received,
                                "relay hop was not observed"
                            );

                            decrypt_for_receiver(
                                &message.data,
                                &signing.public,
                                &receivers,
                            )?;

                            println!(
                                "REAL QUIC A -> B -> C: PASS"
                            );
                            println!(
                                "PINNED SENDER AUTHENTICATION: PASS"
                            );
                            println!(
                                "ML-KEM / ML-DSA / AES-GCM: PASS"
                            );
                            println!(
                                "SHAMIR 3-OF-5 DECRYPTION: PASS"
                            );

                            return Ok::<(), anyhow::Error>(());
                        }

                        _ => {}
                    }
                }

                _ = ticker.tick() => {
                    let ready = a_sees_b
                        && b_sees_a
                        && b_sees_c
                        && c_sees_b;

                    if ready && ready_at.is_none() {
                        ready_at = Some(
                            tokio::time::Instant::now()
                        );
                    }

                    if !published && ready_at.is_some_and(
                        |start| start.elapsed()
                            >= Duration::from_secs(2)
                    ) {
                        a.behaviour_mut()
                            .publish(
                                topic.clone(),
                                packet.clone(),
                            )
                            .map_err(anyhow::Error::msg)?;

                        published = true;
                        println!(
                            "QUIC NODE A: REAL ENCRYPTED MESSAGE PUBLISHED"
                        );
                    }
                }
            }
        }
    };

    match tokio::time::timeout(Duration::from_secs(45), execution).await {
        Ok(result) => result,
        Err(_) => bail!(
            "three-node QUIC delivery timed out; \
             subscribed={a_sees_b}/{b_sees_a}/{b_sees_c}/{c_sees_b}, \
             published={published}, relay_received={relay_received}"
        ),
    }
}
