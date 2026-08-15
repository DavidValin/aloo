//! Shared state for every Gherkin scenario, plus the fixtures that keep the
//! acceptance layer fast enough to run on every commit.
//!
//! One `World` covers all the domains rather than one per feature: a scenario
//! like "a reconnecting peer proves it is still them" legitimately spans the
//! key store, the rotation logic and a live server, and splitting the state up
//! would only move that coupling into the step definitions.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

use cucumber::World;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::net::TcpStream;

use aloo::crypto::KeyPair;
use aloo::idstore::IdStore;
use aloo::proto::{Envelope, ServerMessage, UserId};
use aloo::rekey::{RemoteKeys, ResumeVerification};
use aloo::server::{Outgoing, Registry};
use aloo::ui::ui::{UiAction, UiState};
use aloo::ui::ui_connect_popup::ConnectPopupState;

/// Modulus size for the scenario key pool below.
///
/// Deliberately smaller than `crypto::RSA_KEY_BITS`. Key *size* is not
/// something any scenario asserts - they assert that two keys differ, that a
/// message round-trips, that a signature verifies, and that a payload longer
/// than one block is split (computed from `max_chunk_len`, so it adapts to
/// whatever size is in use). The one requirement that is genuinely about key
/// size, TB-053, is proven by `crypto_test::generate_uses_the_default_rsa_key_bits`
/// against the real constant.
///
/// The difference is not marginal: at 2048 bits this pool alone took ~80
/// seconds on the development machine, which is enough to stop people running
/// the acceptance layer at all.
const SCENARIO_KEY_BITS: usize = 1024;

/// Real RSA keypairs for scenarios, generated **once per distinct name** and
/// only when a scenario actually asks for one.
///
/// Generating fresh keys per scenario would dominate the runtime, and an
/// acceptance suite nobody runs protects nothing. Reusing them changes no
/// behaviour under test: the code paths care that two keys are different,
/// never that they were freshly minted for this particular scenario.
///
/// Generated lazily per name rather than all at once so a filtered run
/// (`cargo bdd -- -t @AC-030`) pays for nothing it does not use - a UI-only
/// selection generates no keys at all. The lock is held across generation on
/// purpose: it serialises concurrent scenarios asking for the same key
/// instead of racing several keygens against each other for the same CPU.
///
/// `test/crypto_test.rs` still generates fresh keys at the real size, so
/// "keygen really does produce usable, distinct keys" stays covered where it
/// belongs rather than being assumed here.
pub fn keypair_for(who: &str) -> KeyPair {
    static POOL: OnceLock<Mutex<HashMap<String, (RsaPrivateKey, RsaPublicKey)>>> = OnceLock::new();
    let pool = POOL.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = pool.lock().expect("key pool lock");
    let (private, public) = guard.entry(who.to_string()).or_insert_with(|| {
        let kp = KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("scenario keygen");
        (kp.private, kp.public)
    });
    KeyPair { private: private.clone(), public: public.clone() }
}

/// State for a single simulated client in a multi-client scenario. The
/// client's own `UserId` lives in `AlooWorld::ids`, keyed by the same
/// handle, so it is not duplicated here.
#[derive(Default)]
pub struct ClientState {
    pub stream: Option<TcpStream>,
    pub received: Vec<ServerMessage>,
}

#[derive(World, Default)]
#[world(init = Self::default)]
pub struct AlooWorld {
    // -- connect popup -------------------------------------------------
    pub popup: Option<ConnectPopupState>,
    pub popup_error: Option<String>,
    pub popup_action: Option<aloo::ui::ui_connect_popup::Action>,
    pub browser_root: Option<std::path::PathBuf>,

    // -- connected UI --------------------------------------------------
    pub ui: Option<UiState>,
    pub last_action: Option<UiAction>,
    pub action_was_none: bool,

    // -- server registry (in-process, no sockets) ----------------------
    pub registry: Option<Registry>,
    pub ids: HashMap<String, UserId>,
    pub emitted: Vec<Outgoing>,
    pub route_error: Option<String>,

    // -- live server over loopback TCP ---------------------------------
    pub addr: Option<SocketAddr>,
    pub clients: HashMap<String, ClientState>,

    // -- encryption ----------------------------------------------------
    pub plaintext: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub derived: HashMap<String, KeyPair>,

    // -- wire protocol -------------------------------------------------
    pub envelope: Option<Envelope>,

    // -- key rotation --------------------------------------------------
    pub remote_keys: Option<RemoteKeys>,
    pub rotation_der: Vec<u8>,
    pub rotation_sig: Vec<u8>,
    pub verification: Option<ResumeVerification>,
    pub flushed: Vec<aloo::rekey::QueuedOutbound>,

    // -- identity pinning ----------------------------------------------
    pub id_store: Option<IdStore>,
    pub id_check: Option<aloo::idstore::IdCheck>,
    pub temp_files: Vec<std::path::PathBuf>,
}

impl std::fmt::Debug for AlooWorld {
    /// Hand-written because most of what the world holds - RSA keys, live
    /// sockets, ratatui state - either has no useful `Debug` or would bury a
    /// failure message in kilobytes of noise. cucumber only needs *something*
    /// printable when a step panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlooWorld")
            .field("has_popup", &self.popup.is_some())
            .field("has_ui", &self.ui.is_some())
            .field("has_registry", &self.registry.is_some())
            .field("clients", &self.clients.keys().collect::<Vec<_>>())
            .field("ids", &self.ids)
            .field("emitted", &self.emitted.len())
            .field("route_error", &self.route_error)
            .field("popup_error", &self.popup_error)
            .finish()
    }
}

impl Drop for AlooWorld {
    fn drop(&mut self) {
        for path in &self.temp_files {
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl AlooWorld {
    pub fn popup_mut(&mut self) -> &mut ConnectPopupState {
        self.popup.get_or_insert_with(ConnectPopupState::new)
    }

    pub fn ui_mut(&mut self) -> &mut UiState {
        self.ui.as_mut().expect("no connected UI in this scenario - a Given step should create one")
    }

    pub fn ui_ref(&self) -> &UiState {
        self.ui.as_ref().expect("no connected UI in this scenario")
    }

    pub fn registry_mut(&mut self) -> &mut Registry {
        self.registry.get_or_insert_with(Registry::new)
    }

    pub fn id_of(&self, name: &str) -> UserId {
        *self
            .ids
            .get(name)
            .unwrap_or_else(|| panic!("no registered user called {name:?}; known: {:?}", self.ids.keys()))
    }

    pub fn client_mut(&mut self, name: &str) -> &mut ClientState {
        self.clients
            .get_mut(name)
            .unwrap_or_else(|| panic!("no connected client called {name:?}"))
    }

    /// A unique path under the system temp dir, removed when the scenario ends.
    pub fn temp_path(&mut self, tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path =
            std::env::temp_dir().join(format!("aloo-cucumber-{tag}-{}-{nanos}", std::process::id()));
        self.temp_files.push(path.clone());
        path
    }
}
