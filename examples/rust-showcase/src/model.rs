use std::fmt;

#[derive(Clone, Copy, Debug)]
pub enum NodeRole {
    Origin,
    Relay,
    Destination,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin => write!(f, "origin"),
            Self::Relay => write!(f, "relay"),
            Self::Destination => write!(f, "destination"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PublicAlgorithmSuite {
    pub signature: &'static str,
    pub key_establishment: &'static str,
    pub authenticated_encryption: &'static str,
    pub threshold_secret_sharing: &'static str,
}

impl Default for PublicAlgorithmSuite {
    fn default() -> Self {
        Self {
            signature: "ML-DSA",
            key_establishment: "ML-KEM",
            authenticated_encryption: "AES-256-GCM",
            threshold_secret_sharing: "Shamir Secret Sharing",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicMessage {
    pub id: u64,
    pub body: String,
    pub fragments: usize,
}

impl PublicMessage {
    pub fn new(id: u64, body: impl Into<String>, fragments: usize) -> Self {
        Self {
            id,
            body: body.into(),
            fragments: fragments.max(1),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum LifecycleStage {
    Create,
    Protect,
    Sign,
    Fragment,
    Transport,
    Verify,
    Reassemble,
    Deliver,
    Cleanup,
}

impl fmt::Display for LifecycleStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Create => "CREATE",
            Self::Protect => "PROTECT",
            Self::Sign => "SIGN",
            Self::Fragment => "FRAGMENT",
            Self::Transport => "TRANSPORT",
            Self::Verify => "VERIFY",
            Self::Reassemble => "REASSEMBLE",
            Self::Deliver => "DELIVER",
            Self::Cleanup => "CLEANUP",
        };
        write!(f, "{label}")
    }
}

#[derive(Clone, Debug)]
pub struct PublicEvent {
    pub node: &'static str,
    pub role: NodeRole,
    pub message_id: u64,
    pub stage: LifecycleStage,
    pub note: &'static str,
}
