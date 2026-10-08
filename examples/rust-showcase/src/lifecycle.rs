use tokio::{sync::mpsc, time::{sleep, Duration}};

use crate::model::{LifecycleStage, NodeRole, PublicEvent, PublicMessage};

async fn emit(
    tx: &mpsc::Sender<PublicEvent>,
    node: &'static str,
    role: NodeRole,
    message_id: u64,
    stage: LifecycleStage,
    note: &'static str,
) {
    let _ = tx
        .send(PublicEvent {
            node,
            role,
            message_id,
            stage,
            note,
        })
        .await;
    sleep(Duration::from_millis(35)).await;
}

pub async fn simulate_three_node_lifecycle(
    message: PublicMessage,
    tx: mpsc::Sender<PublicEvent>,
) {
    let id = message.id;

    emit(&tx, "node-a", NodeRole::Origin, id, LifecycleStage::Create,
        "message created in the public lifecycle model").await;
    emit(&tx, "node-a", NodeRole::Origin, id, LifecycleStage::Protect,
        "authenticated-encryption stage represented").await;
    emit(&tx, "node-a", NodeRole::Origin, id, LifecycleStage::Sign,
        "post-quantum signature stage represented").await;
    emit(&tx, "node-a", NodeRole::Origin, id, LifecycleStage::Fragment,
        "message split into bounded public-model fragments").await;

    emit(&tx, "node-b", NodeRole::Relay, id, LifecycleStage::Transport,
        "relay path active").await;
    emit(&tx, "node-b", NodeRole::Relay, id, LifecycleStage::Transport,
        "temporary path disruption simulated").await;
    sleep(Duration::from_millis(90)).await;
    emit(&tx, "node-b", NodeRole::Relay, id, LifecycleStage::Transport,
        "path recovered; delivery flow continues").await;

    emit(&tx, "node-c", NodeRole::Destination, id, LifecycleStage::Verify,
        "verification and anti-replay stage represented").await;
    emit(&tx, "node-c", NodeRole::Destination, id, LifecycleStage::Reassemble,
        "fragments reassembled in the lifecycle model").await;
    emit(&tx, "node-c", NodeRole::Destination, id, LifecycleStage::Deliver,
        "message delivered to the destination stage").await;
    emit(&tx, "node-c", NodeRole::Destination, id, LifecycleStage::Cleanup,
        "RAM-first cleanup stage represented").await;
}
