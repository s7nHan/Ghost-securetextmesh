//! Independent OS-process QUIC/DTN acceptance, not the commercial production application.
#![forbid(unsafe_code)]
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::StreamExt;
use ghost_public_crypto::{
    primitives::{generate_mldsa87, generate_mlkem768},
    sealed_message::{open_message, seal_message},
    wire::{decode_authenticated_wire, encode_wire},
};
use ghost_public_runtime::{
    dtn::{issue_ack, RamDtnQueue},
    security::{make_pow_packet, verify_pow_packet, RateLimiter},
};
use libp2p::{gossipsub, identity, swarm::SwarmEvent, PeerId, Swarm, SwarmBuilder};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const TEXT: &[u8] = b"GHOST-INDEPENDENT-PROCESS-DTN-ENCRYPTED-PAYLOAD";
const DATA: &str = "ghost-isolated-data-v1";
const RETRY: &str = "ghost-isolated-retry-v1";
const ACK: &str = "ghost-isolated-ack-v1";

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    identity: String,
    address: String,
    a_peer: String,
    b_peer: String,
    c_peer: String,
    sender_pub: String,
    receiver_pub: String,
    receiver_secret: String,
    kem_secrets: Vec<String>,
    packet: String,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.identity.zeroize();
        self.receiver_secret.zeroize();
        self.packet.zeroize();
        for x in &mut self.kem_secrets {
            x.zeroize();
        }
    }
}
fn event(msg: &str) {
    println!("{msg}");
    let _ = std::io::stdout().flush();
}
fn decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        B64.decode(s).context("bad base64 in session")?,
    ))
}
fn peer(s: &str) -> Result<PeerId> {
    Ok(PeerId::from_str(s)?)
}
fn swarm(k: identity::Keypair) -> Swarm<gossipsub::Behaviour> {
    let mut s = SwarmBuilder::with_existing_identity(k)
        .with_tokio()
        .with_quic()
        .with_behaviour(|k| {
            let config = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Strict)
                .heartbeat_interval(Duration::from_millis(300))
                .max_transmit_size(64 * 1024)
                .build()
                .expect("gossipsub config");
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(k.clone()), config)
                .expect("gossipsub signed")
        })
        .expect("quic")
        .build();
    for name in [DATA, RETRY, ACK] {
        s.behaviour_mut()
            .subscribe(&gossipsub::IdentTopic::new(name))
            .expect("subscribe");
    }
    s
}
async fn relay(c: Config, k: identity::Keypair) -> Result<()> {
    let sender = decode(&c.sender_pub)?;
    let receiver = decode(&c.receiver_pub)?;
    let a = peer(&c.a_peer)?;
    let dest = peer(&c.c_peer)?;
    let mut s = swarm(k);
    s.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let mut pending = RamDtnQueue::new();
    let mut limit = RateLimiter::new();
    let mut c_online = false;
    let mut invalid_pow = 0usize;
    let mut unauthorized = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    let data = gossipsub::IdentTopic::new(DATA).hash();
    let retry = gossipsub::IdentTopic::new(RETRY);
    let retry_hash = retry.hash();
    let ack_hash = gossipsub::IdentTopic::new(ACK).hash();
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            tokio::select! {
                e = s.select_next_some() => match e {
                    SwarmEvent::NewListenAddr { address, .. } => event(&format!("READY|{address}")),
                    SwarmEvent::Behaviour(gossipsub::Event::Subscribed {peer_id, topic})
                        if peer_id == dest && topic == retry_hash => {
                        if !c_online { c_online = true; event("C_ONLINE"); }
                    },
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. }
                        if peer_id == dest && num_established == 0 => {
                        c_online = false;
                        event("C_OFFLINE");
                    },
                    SwarmEvent::Behaviour(gossipsub::Event::Message {message, ..})
                        if message.topic == data && message.source == Some(a) => {
                        if !limit.allow(Instant::now()) { continue; }
                        match verify_pow_packet(&message.data) {
                            Ok(wire) => {
                                if pending.enqueue(wire, &sender, &receiver,
                                    Instant::now(), Duration::from_secs(60)).is_ok() {
                                    event("QUEUED");
                                }
                            }
                            Err(_) => invalid_pow += 1,
                        }
                    },
                    SwarmEvent::Behaviour(gossipsub::Event::Message {message, ..})
                        if message.topic == data && message.source != Some(a) => {
                        unauthorized += 1;
                    },
                    SwarmEvent::Behaviour(gossipsub::Event::Message {message, ..})
                        if message.topic == ack_hash && message.source == Some(dest) => {
                        if pending.acknowledge(&message.data, Instant::now()).unwrap_or(false) {
                            ensure!(invalid_pow >= 2, "negative network PoW probes were not rejected");
                            ensure!(unauthorized >= 1, "no unauthorized network packet reached relay");
                            ensure!(pending.len() == 0 && pending.bytes_used() == 0);
                            event("ACK_OK");
                            return Ok::<_, anyhow::Error>(());
                        }
                    },
                    _ => {}
                },
                _ = tick.tick() => {
                    pending.expire(Instant::now());
                    if c_online {
                        if let Some(packet) = pending.next_due(Instant::now()) {
                            if s.behaviour_mut().publish(retry.clone(), packet.to_vec()).is_ok() {
                                pending.record_attempt(Instant::now()).map_err(anyhow::Error::msg)?;
                            }
                        }
                    }
                }
            }
        }
    }).await.context("relay timed out")?
}
async fn sender(c: Config, k: identity::Keypair) -> Result<()> {
    let mut s = swarm(k);
    s.dial(c.address.parse::<libp2p::Multiaddr>()?)?;
    let target = peer(&c.b_peer)?;
    let data = gossipsub::IdentTopic::new(DATA);
    let topic = data.hash();
    let packet = decode(&c.packet)?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic: t }) =
                s.select_next_some().await
            {
                if peer_id == target && t == topic {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    for i in 0..2 {
                        s.behaviour_mut()
                            .publish(data.clone(), format!("invalid-proof-{i}").into_bytes())?;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    s.behaviour_mut().publish(data.clone(), packet.to_vec())?;
                    event("A_PUBLISHED");
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }
    })
    .await
    .context("sender failed to connect")?
}
async fn receiver(c: Config, k: identity::Keypair, warmup: bool) -> Result<()> {
    let mut s = swarm(k);
    s.dial(c.address.parse::<libp2p::Multiaddr>()?)?;
    let relay = peer(&c.b_peer)?;
    let sender_pub = decode(&c.sender_pub)?;
    let sign_pub = decode(&c.receiver_pub)?;
    let sign_sec = decode(&c.receiver_secret)?;
    let keys: Vec<Zeroizing<Vec<u8>>> = c
        .kem_secrets
        .iter()
        .map(|x| decode(x))
        .collect::<Result<_>>()?;
    ensure!(keys.len() == 3, "expected three distinct KEM shares");
    let topic = gossipsub::IdentTopic::new(RETRY).hash();
    let ack_topic = gossipsub::IdentTopic::new(ACK);
    tokio::time::timeout(Duration::from_secs(50), async {
        loop {
            match s.select_next_some().await {
                SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic: t })
                    if peer_id == relay && t == topic && warmup =>
                {
                    event("WARM_READY");
                    tokio::time::sleep(Duration::from_secs(40)).await;
                    return Ok::<_, anyhow::Error>(());
                }
                SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. })
                    if !warmup && message.source == Some(relay) && message.topic == topic =>
                {
                    let verified = decode_authenticated_wire(&message.data, &sender_pub)
                        .map_err(anyhow::Error::msg)?;
                    let plaintext = open_message(
                        &verified,
                        &sender_pub,
                        [
                            (0, keys[0].as_slice()),
                            (2, keys[1].as_slice()),
                            (4, keys[2].as_slice()),
                        ],
                    )
                    .map_err(anyhow::Error::msg)?;
                    ensure!(plaintext.as_slice() == TEXT, "recipient mismatch");
                    drop(plaintext);
                    let ack = issue_ack(
                        verified.message_id,
                        &message.data,
                        &sender_pub,
                        &sign_pub,
                        &sign_sec,
                    )
                    .map_err(anyhow::Error::msg)?;
                    s.behaviour_mut().publish(ack_topic.clone(), ack)?;
                    event("C_AUTHENTICATED_DECRYPTED_ACK_SENT");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return Ok::<_, anyhow::Error>(());
                }
                _ => {}
            }
        }
    })
    .await
    .context("receiver timed out")?
}
async fn attacker(c: Config, k: identity::Keypair) -> Result<()> {
    let mut s = swarm(k);
    s.dial(c.address.parse::<libp2p::Multiaddr>()?)?;
    let b = peer(&c.b_peer)?;
    let data = gossipsub::IdentTopic::new(DATA);
    let topic = data.hash();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic: t }) =
                s.select_next_some().await
            {
                if peer_id == b && t == topic {
                    let mut sent = 0usize;
                    for i in 0..100 {
                        if s.behaviour_mut()
                            .publish(
                                data.clone(),
                                format!("unauthorized-malformed-pow-{i}").into_bytes(),
                            )
                            .is_ok()
                        {
                            sent += 1;
                        }
                        // Poll the swarm so transport receives work during the burst.
                        tokio::select! {
                            _ = s.select_next_some() => {},
                            _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                        }
                    }
                    ensure!(sent > 0, "attacker did not send live packets");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    event("UNTRUSTED_PEER_FLOOD_SENT");
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }
    })
    .await
    .context("attacker failed to connect")?
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(role: &str, c: &Config) -> Result<ChildGuard> {
    let mut p = Command::new(std::env::current_exe()?)
        .arg("--role")
        .arg(role)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn isolated process")?;
    let raw = Zeroizing::new(serde_json::to_vec(c)?);
    p.stdin.take().context("child stdin")?.write_all(&raw)?;
    Ok(ChildGuard(p))
}
fn next(rx: &mpsc::Receiver<String>, want: &str) -> Result<String> {
    let until = Instant::now() + Duration::from_secs(50);
    loop {
        let remain = until.saturating_duration_since(Instant::now());
        let line = rx.recv_timeout(remain).context("process-event timeout")?;
        if line.starts_with("READY|") && want == "READY|" {
            return Ok(line[6..].into());
        }
        if line == want {
            return Ok(line);
        }
    }
}
fn key_string(k: &identity::Keypair) -> Result<String> {
    Ok(B64.encode(k.to_protobuf_encoding()?))
}
#[cfg(target_os = "linux")]
fn memory_snapshot_gate(pid: u32) -> Result<()> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let field = |name: &str| -> Result<u64> {
        let line = status
            .lines()
            .find(|line| line.starts_with(name))
            .context("missing /proc memory metric")?;
        let kib = line.split_whitespace().nth(1).context("memory metric")?;
        Ok(kib.parse()?)
    };
    ensure!(
        field("VmRSS:")? < 512 * 1024,
        "relay memory exceeds 512 MiB"
    );
    ensure!(field("VmSwap:")? == 0, "relay has swapped memory pages");
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))?;
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .context("core dump limit missing")?;
    ensure!(
        core.split_whitespace().nth(4) == Some("0"),
        "core dump file size is not disabled"
    );
    event("LINUX RELAY RSS/SWAP SNAPSHOT AND CORE LIMIT: PASS");
    Ok(())
}
fn controller() -> Result<()> {
    let key_a = identity::Keypair::generate_ed25519();
    let key_b = identity::Keypair::generate_ed25519();
    let key_c = identity::Keypair::generate_ed25519();
    let key_x = identity::Keypair::generate_ed25519();
    let a_peer = key_a.public().to_peer_id().to_string();
    let b_peer = key_b.public().to_peer_id().to_string();
    let c_peer = key_c.public().to_peer_id().to_string();
    let signer = generate_mldsa87();
    let receiver = generate_mldsa87();
    let recipients: [_; 5] = std::array::from_fn(|_| generate_mlkem768());
    let pubs: [Vec<u8>; 5] = std::array::from_fn(|i| recipients[i].public.clone());
    let sealed =
        seal_message(TEXT, &signer.public, &signer.secret, &pubs).map_err(anyhow::Error::msg)?;
    let wire = encode_wire(&sealed).map_err(anyhow::Error::msg)?;
    let packet = make_pow_packet(&wire).map_err(anyhow::Error::msg)?;
    let mut b_cfg = {
        let mut cfg = Config::default();
        cfg.identity = key_string(&key_b)?;
        cfg.a_peer = a_peer.clone();
        cfg.b_peer = b_peer.clone();
        cfg.c_peer = c_peer.clone();
        cfg.sender_pub = B64.encode(&signer.public);
        cfg.receiver_pub = B64.encode(&receiver.public);
        cfg
    };
    let mut b = start("B", &b_cfg)?;
    let (tx, rx) = mpsc::channel();
    let stdout = b.0.stdout.take().context("relay stdout")?;
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if let Ok(line) = line {
                let _ = tx.send(line);
            } else {
                break;
            }
        }
    });
    let address = next(&rx, "READY|")?;
    b_cfg.address = address.clone();
    let c_cfg = {
        let mut cfg = Config::default();
        cfg.identity = key_string(&key_c)?;
        cfg.address = address.clone();
        cfg.a_peer = a_peer.clone();
        cfg.b_peer = b_peer.clone();
        cfg.c_peer = c_peer.clone();
        cfg.sender_pub = B64.encode(&signer.public);
        cfg.receiver_pub = B64.encode(&receiver.public);
        cfg.receiver_secret = B64.encode(&*receiver.secret);
        cfg.kem_secrets = vec![
            B64.encode(&*recipients[0].secret),
            B64.encode(&*recipients[2].secret),
            B64.encode(&*recipients[4].secret),
        ];
        cfg
    };
    let mut warm = start("warmup", &c_cfg)?;
    next(&rx, "C_ONLINE")?;
    warm.0.kill()?;
    warm.0.wait()?;
    next(&rx, "C_OFFLINE")?;
    let x_cfg = {
        let mut cfg = Config::default();
        cfg.identity = key_string(&key_x)?;
        cfg.address = address.clone();
        cfg.b_peer = b_peer.clone();
        cfg
    };
    let mut x = start("X", &x_cfg)?;
    ensure!(
        x.0.wait()?.success(),
        "untrusted network-flood process failed"
    );
    #[cfg(target_os = "linux")]
    memory_snapshot_gate(b.0.id())?;
    while let Ok(line) = rx.try_recv() {
        ensure!(line != "QUEUED", "untrusted network packet was accepted");
    }
    let a_cfg = {
        let mut cfg = Config::default();
        cfg.identity = key_string(&key_a)?;
        cfg.address = address.clone();
        cfg.a_peer = a_peer;
        cfg.b_peer = b_peer;
        cfg.c_peer = c_peer;
        cfg.packet = B64.encode(&packet);
        cfg
    };
    let mut a = start("A", &a_cfg)?;
    next(&rx, "QUEUED")?;
    let mut c = start("C", &c_cfg)?;
    next(&rx, "ACK_OK")?;
    ensure!(a.0.wait()?.success(), "sender process failed");
    ensure!(c.0.wait()?.success(), "receiver process failed");
    ensure!(b.0.wait()?.success(), "relay process failed");
    event("REAL INDEPENDENT PROCESSES: PASS");
    event("C RESTART, DTN DELIVERY, SIGNED ACK: PASS");
    event("NETWORK NEGATIVE TESTS AND PINNED ORIGIN: PASS");
    event("SESSION CONFIGURATION USED STDIN PIPES, NO SESSION FILES CREATED");
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let arg: Vec<String> = std::env::args().collect();
    if arg.len() == 1 {
        return controller();
    }
    ensure!(arg.len() == 3 && arg[1] == "--role", "invalid invocation");
    let mut raw = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut raw)?;
    ensure!(raw.len() < 100_000, "oversized role config");
    let config: Config = serde_json::from_str(&raw)?;
    raw.zeroize();
    let encoded = decode(&config.identity)?;
    let key = identity::Keypair::from_protobuf_encoding(&encoded)?;
    match arg[2].as_str() {
        "A" => sender(config, key).await,
        "B" => relay(config, key).await,
        "C" => receiver(config, key, false).await,
        "warmup" => receiver(config, key, true).await,
        "X" => attacker(config, key).await,
        _ => bail!("unrecognized role"),
    }
}
