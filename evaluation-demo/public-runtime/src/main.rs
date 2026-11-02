//! GHOST independent security evaluation.
#![forbid(unsafe_code)]

use anyhow::{bail, ensure, Context, Result};
use futures::StreamExt;
use ghost_public_crypto::{
    primitives::{generate_mldsa87, generate_mlkem768},
    sealed_message::{open_message, seal_message},
    wire::{decode_authenticated_wire, encode_wire},
};
use ghost_public_runtime::dtn::{issue_ack, RamDtnQueue};
use ghost_public_runtime::security::{make_pow_packet, verify_pow_packet, RateLimiter};
use libp2p::{gossipsub, identity, swarm::SwarmEvent, Swarm, SwarmBuilder};
use std::time::Duration;
use zeroize::Zeroizing;

const DATA: &str = "ghost-public-dtn-data-v1";
const ACK: &str = "ghost-public-dtn-ack-v1";
const RETRY: &str = "ghost-public-dtn-retry-v1";
const PLAINTEXT: &[u8] = b"GHOST REAL QUIC DTN RECOVERY AND VERIFIED ACK";

fn node(
    key: identity::Keypair,
    data: &gossipsub::IdentTopic,
    ack: &gossipsub::IdentTopic,
    retry: &gossipsub::IdentTopic,
) -> Swarm<gossipsub::Behaviour> {
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(350))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(64 * 1024)
                .build()
                .expect("Gossipsub configuration");

            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)
                .expect("signed Gossipsub")
        })
        .expect("QUIC transport")
        .build();

    swarm
        .behaviour_mut()
        .subscribe(data)
        .expect("data subscription");
    swarm
        .behaviour_mut()
        .subscribe(ack)
        .expect("ACK subscription");
    swarm
        .behaviour_mut()
        .subscribe(retry)
        .expect("retry subscription");

    swarm
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connect,
    Disconnect,
    OfflinePublish,
    WaitForQueue,
    Reconnect,
    Deliver,
    WaitForAck,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let sender = generate_mldsa87();
    let receiver_signing = generate_mldsa87();
    let receivers: [_; 5] = std::array::from_fn(|_| generate_mlkem768());
    let public_keys: [Vec<u8>; 5] = std::array::from_fn(|i| receivers[i].public.clone());

    let sealed = seal_message(PLAINTEXT, &sender.public, &sender.secret, &public_keys)
        .map_err(anyhow::Error::msg)?;

    let encrypted_wire = encode_wire(&sealed).map_err(anyhow::Error::msg)?;

    let pow_packet = make_pow_packet(&encrypted_wire).map_err(anyhow::Error::msg)?;

    let identity_a = identity::Keypair::generate_ed25519();
    let identity_b = identity::Keypair::generate_ed25519();
    let identity_c = identity::Keypair::generate_ed25519();

    let id_a = identity_a.public().to_peer_id();
    let id_b = identity_b.public().to_peer_id();
    let id_c = identity_c.public().to_peer_id();

    ensure!(id_a != id_b && id_b != id_c && id_a != id_c);

    let data_topic = gossipsub::IdentTopic::new(DATA);
    let ack_topic = gossipsub::IdentTopic::new(ACK);
    let retry_topic = gossipsub::IdentTopic::new(RETRY);
    let data_hash = data_topic.hash();
    let ack_hash = ack_topic.hash();
    let retry_hash = retry_topic.hash();

    let mut a = node(identity_a, &data_topic, &ack_topic, &retry_topic);
    let mut b = node(identity_b, &data_topic, &ack_topic, &retry_topic);
    let mut c = node(identity_c, &data_topic, &ack_topic, &retry_topic);

    b.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;

    let address_b = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = b.select_next_some().await {
                break address;
            }
        }
    })
    .await
    .context("B did not listen")?;

    a.dial(address_b.clone())?;
    c.dial(address_b.clone())?;

    let mut a_b = false;
    let mut b_a = false;
    let mut b_c = false;
    let mut c_b = false;
    let mut b_c_ack = false;
    let mut c_b_ack = false;

    let mut phase = Phase::Connect;
    let mut entered = tokio::time::Instant::now();
    let mut initial_ready = false;
    let mut queued = false;
    let mut delivered = false;
    let mut ack_outbox: Option<Vec<u8>> = None;
    let mut queue = RamDtnQueue::new();
    let mut ingress = RateLimiter::new();

    let mut tick = tokio::time::interval(Duration::from_millis(150));

    let scenario = async {
        loop {
            tokio::select! {
                        event = a.select_next_some() => {
                            if let SwarmEvent::Behaviour(
                                gossipsub::Event::Subscribed {
                                    peer_id, topic
                                }
                            ) = event {
                                if peer_id == id_b && topic == data_hash {
                                    a_b = true;
                                }
                            }
                        }

                        event = b.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(
                                    gossipsub::Event::Subscribed {
                                        peer_id, topic
                                    }
                                ) => {
                                    if peer_id == id_a && topic == data_hash {
                                        b_a = true;
                                    }
                                    if peer_id == id_c && topic == data_hash {
                                        b_c = true;
                                    }
                                    if peer_id == id_c && topic == ack_hash {
                                        b_c_ack = true;
                                    }
                                }

                                SwarmEvent::Behaviour(
                                    gossipsub::Event::Message {
                                        message, ..
                                    }
                                ) if message.topic == data_hash
                                    && message.source == Some(id_a) => {
                                    ensure!(
                                        phase == Phase::WaitForQueue,
                                        "Unexpected original message phase"
                                    );
                                    ensure!(
                                        !b.connected_peers().any(|peer| *peer == id_c),
                                        "Receiver was not disconnected"
                                    );

                                    let Some(verified_wire) = (
                                if ingress.allow(std::time::Instant::now()) {
                                    verify_pow_packet(&message.data).ok()
                                } else {
                                    None
                                }
                            ) else {
                                continue;
                            };

                            queue.enqueue(
                                        verified_wire,
                                        &sender.public,
                                        &receiver_signing.public,
                                        std::time::Instant::now(),
                                        Duration::from_secs(120),
                                    ).map_err(anyhow::Error::msg)?;

                                    queued = true;
                                    println!("DTN OFFLINE ENCRYPTED RAM QUEUE: PASS");
                                }

                                SwarmEvent::Behaviour(
                                    gossipsub::Event::Message {
                                        message, ..
                                    }
                                ) if message.topic == ack_hash => {
                                    ensure!(
                                        message.source == Some(id_c),
                                        "ACK did not originate from pinned C Peer ID"
                                    );
                                    ensure!(delivered, "ACK preceded decryption");

                                    let released = queue.acknowledge(
                                        &message.data,
                                        std::time::Instant::now(),
                                    ).map_err(anyhow::Error::msg)?;

                                    ensure!(released, "ACK did not release delivery");
                                    ensure!(queue.len() == 0);
                                    ensure!(queue.bytes_used() == 0);

                                    println!("DTN REAL RECONNECT DELIVERY: PASS");
                                    println!("PINNED RECEIVER SIGNED ACK: PASS");
                                    println!("DTN RAM QUEUE RELEASED AFTER ACK: PASS");
                                    println!("PRODUCTION-INDEPENDENT CRYPTO: PASS");
                                    return Ok::<(), anyhow::Error>(());
                                }

                                _ => {}
                            }
                        }

                        event = c.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(
                                    gossipsub::Event::Subscribed {
                                        peer_id, topic
                                    }
                                ) if peer_id == id_b => {
                                    if topic == data_hash {
                                        c_b = true;
                                    }
                                    if topic == ack_hash {
                                        c_b_ack = true;
                                    }
                                }

                                SwarmEvent::Behaviour(
                                    gossipsub::Event::Message {
                                        message, ..
                                    }
                                ) if message.topic == retry_hash => {
                                    ensure!(
                                        phase == Phase::Deliver
                                            || phase == Phase::WaitForAck,
                                        "Message arrived outside recovery phase"
                                    );
                                    ensure!(
                                        message.source == Some(id_b),
                                        "Queued delivery did not come from relay B"
                                    );
                                    ensure!(queued, "Message was not RAM queued");

                                    if !delivered {
                                        let authentic = decode_authenticated_wire(
                                            &message.data,
                                            &sender.public,
                                        ).map_err(anyhow::Error::msg)?;

                                        let plaintext = Zeroizing::new(open_message(
                                            &authentic,
                                            &sender.public,
                                            [
                                                (0, receivers[0].secret.as_slice()),
                                                (2, receivers[2].secret.as_slice()),
                                                (4, receivers[4].secret.as_slice()),
                                            ],
                                        ).map_err(anyhow::Error::msg)?);

                                        ensure!(
                                            plaintext.as_slice() == PLAINTEXT,
                                            "Recovered plaintext mismatch"
                                        );

                                        delivered = true;

                                        ack_outbox = Some(issue_ack(
                                            authentic.message_id,
                                            &message.data,
                                            &sender.public,
                                            &receiver_signing.public,
                                            &receiver_signing.secret,
                                        ).map_err(anyhow::Error::msg)?);

                                        phase = Phase::WaitForAck;
                                        entered = tokio::time::Instant::now();
                                        println!("DTN RECEIVER AUTHENTICATED AND DECRYPTED");
                                    }
                                }

                                _ => {}
                            }
                        }

                        _ = tick.tick() => {
                            match phase {
                                Phase::Connect => {
                                    let ready = a_b && b_a && b_c && c_b
                                        && b_c_ack && c_b_ack;

                                    if ready {
                                        if !initial_ready {
                                            initial_ready = true;
                                            entered = tokio::time::Instant::now();
                                        }

                                        if entered.elapsed()
                                            >= Duration::from_secs(2)
                                        {
                                            c.disconnect_peer_id(id_b)
            .map_err(|_| anyhow::anyhow!("Receiver C disconnect failed"))?;
                                            phase = Phase::Disconnect;
                                            entered = tokio::time::Instant::now();
                                            println!("DTN RECEIVER C DISCONNECTED");
                                        }
                                    }
                                }

                                Phase::Disconnect => {
                                    let b_offline = !b.connected_peers()
                                        .any(|peer| *peer == id_c);
                                    let c_offline = !c.connected_peers()
                                        .any(|peer| *peer == id_b);

                                    if b_offline && c_offline {
                                        phase = Phase::OfflinePublish;
                                        entered = tokio::time::Instant::now();
                                    }
                                }

                                Phase::OfflinePublish => {
                                    if entered.elapsed()
                                        >= Duration::from_secs(2)
                                    {
                                        if a.behaviour_mut().publish(
                                            data_topic.clone(),
                                            pow_packet.clone(),
                                        ).is_ok() {
                                            phase = Phase::WaitForQueue;
                                            println!("DTN SENDER A PUBLISHED WHILE C OFFLINE");
                                        }
                                    }
                                }

                                Phase::WaitForQueue => {
                                    if queued {
                                        ensure!(queue.len() == 1);
                                        ensure!(queue.bytes_used() > 0);

                                        queue.record_attempt(
                                            std::time::Instant::now(),
                                        ).map_err(anyhow::Error::msg)?;

                                        c.dial(address_b.clone())?;
                                        phase = Phase::Reconnect;
                                        entered = tokio::time::Instant::now();

                                        println!("DTN RECEIVER C RECONNECT REQUESTED");
                                    }
                                }

                                Phase::Reconnect => {
                                    let connected = b.connected_peers()
                                        .any(|peer| *peer == id_c)
                                        && c.connected_peers()
                                            .any(|peer| *peer == id_b);

                                    if connected
                                        && entered.elapsed()
                                            >= Duration::from_secs(3)
                                    {
                                        phase = Phase::Deliver;
                                    }
                                }

                                Phase::Deliver => {
                                    if let Some(packet) = queue.next_due(
                                        std::time::Instant::now()
                                    ) {
                                        let packet = packet.to_vec();

                                        if b.behaviour_mut().publish(
                                            retry_topic.clone(),
                                            packet,
                                        ).is_ok() {
                                            queue.record_attempt(
                                                std::time::Instant::now(),
                                            ).map_err(anyhow::Error::msg)?;
                                            println!("DTN RELAY B RETRIED ENCRYPTED PACKET");
                                        }
                                    }
                                }

                                Phase::WaitForAck => {
                                    if let Some(wire) = ack_outbox.as_ref() {
                                        if c.behaviour_mut().publish(
                                            ack_topic.clone(),
                                            wire.clone(),
                                        ).is_ok() {
                                            ack_outbox = None;
                                            println!("DTN RECEIVER C PUBLISHED SIGNED ACK");
                                        }
                                    }
                                }
                            }
                        }
                    }
        }
    };

    match tokio::time::timeout(Duration::from_secs(75), scenario).await {
        Ok(result) => result,
        Err(_) => bail!(
            "DTN QUIC recovery timed out; queued={}, delivered={}",
            queued,
            delivered
        ),
    }
}
