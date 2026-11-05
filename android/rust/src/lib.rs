//! UniFFI surface exposing netdrop to the Android app.
//!
//! # Status
//!
//! This crate is **the interface contract, not the implementation**. Every method on
//! [`NetdropService`] returns [`NetdropError::NotImplemented`] until `netdrop-core` and
//! `nsen-core` exist (roadmap Phases 1-3).
//!
//! It compiles and runs `uniffi-bindgen` today on purpose: the generated Kotlin is a
//! working stub, so the app shell in `../app` can be built and iterated against it in
//! parallel with the core extraction, rather than waiting on Phase 3 to finish.
//!
//! # Threading contract
//!
//! Every exported method is non-blocking or short. Transfers run on Rust-owned threads
//! and report back through [`NetdropEvents`]. In particular [`NetdropEvents::on_offer`]
//! **returns immediately** — the app decides later and calls
//! [`NetdropService::respond_to_offer`].
//!
//! This is not a style preference. UniFFI callbacks execute synchronously on the calling
//! Rust thread, so a blocking `on_offer() -> bool` would park the receiver thread inside
//! a JNI call while Kotlin waited on a latch — and produce an ANR if it were ever invoked
//! from the main thread.

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum NetdropError {
    /// The requested operation has not been implemented yet. Every method currently
    /// returns this; it disappears as Phases 1-3 land.
    #[error("not implemented yet: {reason}")]
    NotImplemented { reason: String },

    #[error("network error: {message}")]
    Network { message: String },

    /// Decryption or authentication failed. Deliberately carries no detail — never leak
    /// plaintext structure through an error message.
    #[error("decryption failed")]
    Crypto,

    #[error("protocol error: {message}")]
    Protocol { message: String },

    /// The peer refused the transfer.
    #[error("rejected by peer")]
    Rejected,

    /// Cancelled locally, via [`NetdropService::cancel`].
    #[error("cancelled")]
    Cancelled,

    /// A wire filename failed the traversal guard.
    #[error("unsafe filename rejected: {name}")]
    RejectedFilename { name: String },

    #[error("storage error: {message}")]
    Storage { message: String },
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// A discovered device. Mirrors `netdrop::discovery::Peer`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub port: u16,
}

/// An incoming transfer offer, shown in the Accept/Reject prompt.
/// Mirrors `netdrop::protocol::Offer`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferInfo {
    pub transfer_id: String,
    pub sender_name: String,
    pub sender_id: String,
    pub filename: String,
    pub size: u64,
    pub is_dir: bool,
}

/// One file in an outgoing transfer, as enumerated by the Kotlin side.
///
/// `token` is an opaque handle — in practice a SAF content URI string — passed back to
/// [`FileProvider::open_read`]. Rust never parses it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryMeta {
    /// '/'-separated, validated on the Rust side: no `..`, no absolute paths.
    pub relative_path: String,
    pub size: u64,
    pub token: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceConfig {
    /// Friendly name advertised over mDNS.
    pub device_name: String,
    /// Stable device id (32 hex chars). Generated and persisted by the app.
    pub device_id: String,
    /// Control port; 4445 to match the desktop default.
    pub control_port: u16,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum SendTarget {
    /// A peer found over mDNS.
    Discovered { peer: PeerInfo },
    /// Manually entered address. Required fallback for Wi-Fi client isolation and for
    /// L3 VPNs such as WireGuard, where multicast never traverses the tunnel but the
    /// unicast transfer works fine.
    Manual { addr: String, port: u16 },
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

// ---------------------------------------------------------------------------
// Callback interfaces (Rust -> Kotlin)
// ---------------------------------------------------------------------------

/// Events pushed from Rust into the app. Implementations must not block.
#[uniffi::export(callback_interface)]
pub trait NetdropEvents: Send + Sync {
    /// The discovered-peer set changed. Carries the full current list, not a delta.
    fn on_peers_changed(&self, peers: Vec<PeerInfo>);

    /// An incoming offer needs a decision. **Returns immediately**; the app answers via
    /// [`NetdropService::respond_to_offer`].
    fn on_offer(&self, offer: OfferInfo);

    /// Byte progress. Already throttled on the Rust side to ~10 Hz — throttle again to
    /// ≤2 Hz before touching `NotificationManager`, which silently drops excess updates
    /// in a way that reads as "the transfer is stuck".
    fn on_progress(&self, transfer_id: String, done: u64, total: u64);

    fn on_finished(&self, transfer_id: String, ok: bool, message: String);

    /// Rust-side logging, bridged to logcat.
    fn on_log(&self, level: LogLevel, message: String);
}

/// File access, delegated to Kotlin because Android storage is SAF, not paths.
///
/// # Descriptor ownership
///
/// `open_read`/`open_write` return a raw fd from `ParcelFileDescriptor.detachFd()`,
/// which **transfers ownership to Rust** — Kotlin cannot recover or close it afterwards.
/// The Rust side must wrap it in a `File` immediately so `Drop` closes it.
///
/// Files are opened lazily, one at a time. Android's default per-process fd limit is
/// 1024, so a 5,000-file folder would exhaust it if entries were opened eagerly. This is
/// the failure that works on a 20-file test folder and dies on a real photo library.
#[uniffi::export(callback_interface)]
pub trait FileProvider: Send + Sync {
    /// Enumerate everything to be sent, or the destination tree for a receive.
    fn list(&self) -> Vec<EntryMeta>;

    /// Open `token` for reading. Returns a detached fd, or -1 on failure.
    fn open_read(&self, token: String) -> i32;

    /// Create `relative_path` for writing. Returns a detached fd, or -1 on failure.
    ///
    /// Implementations should stage under a `.part` name and rename on
    /// [`FileProvider::finish`], so a killed transfer never leaves a partial file
    /// masquerading as a complete one.
    fn open_write(&self, relative_path: String, size: u64) -> i32;

    /// Commit the transfer: rename staged files into place.
    fn finish(&self, ok: bool);
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// The app's handle to netdrop.
///
/// Lifetime note: this owns Rust threads and a `MulticastLock`-dependent mDNS browser.
/// Kotlin must call [`NetdropService::shutdown`] explicitly — relying on `Drop` alone
/// leaks the discovery threads, because UniFFI object destruction is tied to the JVM's
/// cleaner rather than to scope exit.
#[derive(uniffi::Object)]
pub struct NetdropService {
    #[allow(dead_code)]
    config: ServiceConfig,
    #[allow(dead_code)]
    events: Box<dyn NetdropEvents>,
}

#[uniffi::export]
impl NetdropService {
    #[uniffi::constructor]
    pub fn new(config: ServiceConfig, events: Box<dyn NetdropEvents>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { config, events })
    }

    /// Bind the control port and start accepting offers.
    /// Returns the bound port (Phase 3 makes this ephemeral rather than fixed at 4445).
    pub fn start_receiver(&self, _sink: Box<dyn FileProvider>) -> Result<u16, NetdropError> {
        Err(NetdropError::NotImplemented {
            reason: "receiver needs netdrop-core (roadmap Phase 3)".into(),
        })
    }

    pub fn stop_receiver(&self) {}

    /// Answer an offer previously delivered to [`NetdropEvents::on_offer`].
    pub fn respond_to_offer(&self, _transfer_id: String, _accept: bool) {}

    /// Begin advertising and browsing over mDNS.
    ///
    /// The caller **must** hold a `WifiManager.MulticastLock` for the duration. Without
    /// it Android silently drops multicast and discovery finds nothing while appearing
    /// to work.
    pub fn start_discovery(&self) -> Result<(), NetdropError> {
        Err(NetdropError::NotImplemented {
            reason: "discovery needs netdrop-core (roadmap Phase 3)".into(),
        })
    }

    pub fn stop_discovery(&self) {}

    pub fn peers(&self) -> Vec<PeerInfo> {
        Vec::new()
    }

    /// Start an outgoing transfer. Returns a transfer id for progress correlation.
    pub fn send(
        &self,
        _target: SendTarget,
        _files: Box<dyn FileProvider>,
    ) -> Result<String, NetdropError> {
        Err(NetdropError::NotImplemented {
            reason: "send needs nsen-core + netdrop-core (roadmap Phases 1-3)".into(),
        })
    }

    /// Cooperatively cancel an in-flight transfer. Takes effect within ~1 s.
    pub fn cancel(&self, _transfer_id: String) {}

    /// Stop every background thread and release resources. Not idempotent-safe to skip.
    pub fn shutdown(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullEvents;
    impl NetdropEvents for NullEvents {
        fn on_peers_changed(&self, _: Vec<PeerInfo>) {}
        fn on_offer(&self, _: OfferInfo) {}
        fn on_progress(&self, _: String, _: u64, _: u64) {}
        fn on_finished(&self, _: String, _: bool, _: String) {}
        fn on_log(&self, _: LogLevel, _: String) {}
    }

    fn config() -> ServiceConfig {
        ServiceConfig {
            device_name: "Test".into(),
            device_id: "0".repeat(32),
            control_port: 4445,
        }
    }

    /// The contract is wired up and the stubs fail loudly rather than silently no-op'ing.
    #[test]
    fn stubs_report_not_implemented() {
        let svc = NetdropService::new(config(), Box::new(NullEvents));
        assert!(matches!(
            svc.start_discovery(),
            Err(NetdropError::NotImplemented { .. })
        ));
        assert!(svc.peers().is_empty());
    }
}
