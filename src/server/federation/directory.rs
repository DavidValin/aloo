//! Which federated server owns each nickname and channel
//! (docs/PROTOCOL.md's federation section) - built from this server's own
//! registrations, a `DirectorySnapshot` exchanged when a peer link comes
//! up, and incremental gossip (`NicknameRegistered`/`ChannelRegistered`/
//! `ChannelRemoved`/`NicknameRemoved`) after that.
//!
//! Nicknames are persisted (`nicknames` file, one `<name>\t<spec>` line
//! each) because nicknames are themselves durable - `users_registry` is
//! on-disk - so a directory that forgot remote ownership across a restart
//! could let a colliding local registration through before peers
//! reconnect. Channels are in-memory only, rebuilt from the next
//! `DirectorySnapshot`: that matches `channels_registry::ChannelsRegistry`
//! itself, which is entirely in-memory and resets on restart, so a channel
//! directory that outlived the channel it describes would be actively
//! wrong, not just stale.
//!
//! Every mutation here - whether it originates from this server's own
//! registration/creation or from a peer's gossip - goes through the same
//! merge logic (`Ownership::merge`/`merge_channel_entry`). That symmetry
//! matters: a name recorded locally *after* a peer's claim for it already
//! arrived must become `Conflicted` exactly as readily as a peer's claim
//! arriving after a local one already exists - there is no "local always
//! wins because it wrote first" shortcut anywhere in this file.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use super::proto::FederatedChannelInfo;

/// Who owns a nickname, from this server's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// Owned by exactly one federated server (this one, or a peer).
    Owned(String),
    /// Two or more servers claim this name - discovered either by
    /// concurrent creation or by federating two already-populated servers
    /// whose namespaces overlapped. Refused for any *new*
    /// login/registration/creation federation-wide until an operator
    /// manually renames or removes one side; an account or channel
    /// already in this state is never dropped or kicked automatically.
    Conflicted(Vec<String>),
}

impl Ownership {
    /// Merges in a claim that `owner` also owns this name - `self`
    /// unchanged (already `Owned(owner)`), upgraded to `Conflicted` (a
    /// different single owner, or a new claimant added to an existing
    /// conflict).
    fn merge(&mut self, owner: &str) {
        match self {
            Ownership::Owned(existing) if existing == owner => {}
            Ownership::Owned(existing) => {
                *self = Ownership::Conflicted(vec![existing.clone(), owner.to_string()]);
            }
            Ownership::Conflicted(owners) => {
                if !owners.iter().any(|o| o == owner) {
                    owners.push(owner.to_string());
                }
            }
        }
    }
}

/// Who owns a channel name, from this server's point of view - the
/// channel-side analogue of `Ownership`, carrying each claimant's full
/// `FederatedChannelInfo` (kind included) rather than a bare server id,
/// since there is no separate table to look that up in the way
/// `users_registry` backs a nickname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelOwnership {
    Owned(FederatedChannelInfo),
    /// Same meaning as `Ownership::Conflicted`: refused for any *new*
    /// creation or federation join-proxy until an operator resolves it,
    /// but a channel already local to a server (as its true owner, or as
    /// a mirror with real local members) is never touched by this alone.
    Conflicted(Vec<FederatedChannelInfo>),
}

fn merge_channel_entry(existing: &mut ChannelOwnership, info: FederatedChannelInfo) {
    match existing {
        ChannelOwnership::Owned(current) if current.owner == info.owner => {
            *current = info;
        }
        ChannelOwnership::Owned(current) => {
            crate::log_warn!(
                "federation channel name conflict: '{}' is claimed by both '{}' and '{}' - \
                 not proxy-routable until an operator renames one",
                info.name,
                current.owner,
                info.owner
            );
            *existing = ChannelOwnership::Conflicted(vec![current.clone(), info]);
        }
        ChannelOwnership::Conflicted(owners) => {
            if !owners.iter().any(|o| o.owner == info.owner) {
                owners.push(info);
            }
        }
    }
}

/// `~/.aloo/federation_directory` (`crate::platform::aloo_dir`) - the
/// default root a production server keeps its directory under; tests pass
/// a temp dir.
pub fn default_dir() -> PathBuf {
    crate::platform::aloo_dir().join("federation_directory")
}

fn nicknames_path(dir: &std::path::Path) -> PathBuf {
    dir.join("nicknames")
}

pub struct FederationDirectory {
    nicknames: HashMap<String, Ownership>,
    channels: HashMap<String, ChannelOwnership>,
    dir: PathBuf,
    /// Held for as long as this handle lives, when it was opened with
    /// `open_exclusive` - see there for what it is protecting against.
    _lock: Option<std::fs::File>,
}

impl FederationDirectory {
    /// Opens (creating if needed) the directory rooted at `dir`, loading
    /// whatever nickname ownership was persisted from a previous run.
    ///
    /// A file that isn't there yet starts empty - an ordinary first run.
    /// A file that *is* there but cannot be read is an error, not an
    /// empty start: this file is the only record of which nicknames this
    /// federation has already handed out, and quietly forgetting it is
    /// precisely the failure it exists to prevent (another server then
    /// registers a name this one already owns, with no conflict detected
    /// on the forgetful side). Individual unparseable *lines* are still
    /// skipped - one damaged line should not cost the whole file - and
    /// every write is atomic, so a half-written file is not a state that
    /// can be reached in the first place.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let nicknames = match std::fs::read_to_string(nicknames_path(&dir)) {
            Ok(contents) => parse_nicknames(&contents),
            Err(e) if e.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            nicknames,
            channels: HashMap::new(),
            dir,
            _lock: None,
        })
    }

    /// `open`, claiming the directory exclusively for as long as the
    /// returned handle lives. `Ok(None)` means another process already
    /// holds it.
    ///
    /// Two processes genuinely do write this file: a running server, and
    /// `aloo --register-user`, which `docker-server`'s entrypoint runs for
    /// each `ALOO_REGISTER_USERS` entry. Each writes it *whole*, from its
    /// own in-memory copy, so without this the later write silently drops
    /// everything the other did in between - the CLI reading before a
    /// registration and writing after it is enough to erase a nickname the
    /// server had just gossiped in. Holding the lock across a whole
    /// read-modify-write also removes the CLI's own check-then-record
    /// window, where a name could be claimed by a peer between being
    /// judged free and being written.
    ///
    /// The intended usage is exactly what the docs already describe:
    /// register accounts *before* starting the server. A CLI run against a
    /// live server is refused with a message saying so, rather than
    /// quietly corrupting the directory.
    pub fn open_exclusive(dir: PathBuf) -> io::Result<Option<Self>> {
        std::fs::create_dir_all(&dir)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join(".lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        let mut directory = Self::open(dir)?;
        directory._lock = Some(lock);
        Ok(Some(directory))
    }

    /// Drops every claim `owner` holds, for a peer that is gone for good
    /// (`aloo --forget-federation-peer`), and says how many names that
    /// freed. A name that peer *shared* with another server keeps the
    /// other server's claim - `Conflicted` minus one claimant is a clean
    /// `Owned` for whoever is left, exactly as a removal gossiped over a
    /// live link would have left it.
    ///
    /// Deliberately an explicit operator action rather than something
    /// derived from the peer list: a server legitimately knows about
    /// names owned by servers it does not itself peer with, learned
    /// through one they share (a hub topology is entirely normal here), so
    /// "not in my `server_federation_peer` lines" does not mean "gone".
    pub fn forget_owner(&mut self, owner: &str) -> io::Result<usize> {
        let claimed: Vec<String> = self
            .nicknames
            .iter()
            .filter(|(_, ownership)| match ownership {
                Ownership::Owned(o) => o == owner,
                Ownership::Conflicted(owners) => owners.iter().any(|o| o == owner),
            })
            .map(|(name, _)| name.clone())
            .collect();
        let freed = claimed.len();
        for nickname in claimed {
            self.remove_nickname(&nickname, owner)?;
        }
        let channels: Vec<String> = self
            .channels
            .iter()
            .filter(|(_, ownership)| match ownership {
                ChannelOwnership::Owned(info) => info.owner == owner,
                ChannelOwnership::Conflicted(infos) => infos.iter().any(|i| i.owner == owner),
            })
            .map(|(name, _)| name.clone())
            .collect();
        for channel in channels {
            self.remove_channel(&channel, owner);
        }
        Ok(freed)
    }

    /// The refusal shown when `open_exclusive` finds the directory taken.
    pub fn busy_message() -> String {
        "the federation directory is in use by another aloo process (a running server, most \
         likely) - stop it first, or register accounts before starting it"
            .to_string()
    }

    /// Writes the nickname directory out whole, atomically: to a temporary
    /// file first, then renamed over the real one.
    ///
    /// A plain `write` truncates and refills in place, so a crash, a full
    /// disk or a container stopped at the wrong moment leaves a *partial*
    /// file - the tail of the directory silently gone, and every nickname
    /// in it free for another server to claim. `rename` within one
    /// directory is atomic on every platform this runs on: a reader sees
    /// either the whole previous file or the whole new one.
    fn save_nicknames(&self) -> io::Result<()> {
        let mut lines: Vec<(&String, &Ownership)> = self.nicknames.iter().collect();
        lines.sort_by_key(|(name, _)| (*name).clone());
        let contents: String = lines
            .into_iter()
            .map(|(name, ownership)| format!("{name}\t{}\n", encode_ownership(ownership)))
            .collect();
        let final_path = nicknames_path(&self.dir);
        let temp_path = self.dir.join("nicknames.writing");
        std::fs::write(&temp_path, contents)?;
        std::fs::rename(&temp_path, &final_path)
    }

    pub fn owner_of_nickname(&self, nickname: &str) -> Option<&Ownership> {
        self.nicknames.get(nickname)
    }

    /// The clean, single-owner case only - `None` for both an unknown
    /// name and a `Conflicted` one, since neither has one real answer.
    /// Use `channel_is_conflicted` to tell those two apart when it
    /// matters (refusing a *new* creation needs to, since only one of
    /// them should allow it).
    pub fn owner_of_channel(&self, name: &str) -> Option<&FederatedChannelInfo> {
        match self.channels.get(name) {
            Some(ChannelOwnership::Owned(info)) => Some(info),
            _ => None,
        }
    }

    /// Whether `name` is currently claimed by more than one federated
    /// server - checked before allowing a *new* local creation of the
    /// same name, so a third server can't add yet another conflicting
    /// claim on top of one that already exists (`owner_of_channel` alone
    /// cannot tell "nobody" apart from "conflicted", and only "nobody"
    /// should ever allow a fresh creation to proceed).
    pub fn channel_is_conflicted(&self, name: &str) -> bool {
        matches!(self.channels.get(name), Some(ChannelOwnership::Conflicted(_)))
    }

    /// Every nickname/channel this server's directory currently knows -
    /// what a newly linked peer is sent as its `DirectorySnapshot`. A
    /// conflicted name is re-announced under every claimant, so a peer
    /// merging this snapshot reconstructs the identical conflict rather
    /// than silently dropping one side of it.
    pub fn snapshot(&self) -> (Vec<(String, String)>, Vec<FederatedChannelInfo>) {
        let nicknames = self
            .nicknames
            .iter()
            .flat_map(|(name, ownership)| match ownership {
                Ownership::Owned(owner) => vec![(name.clone(), owner.clone())],
                Ownership::Conflicted(owners) => {
                    owners.iter().map(|o| (name.clone(), o.clone())).collect()
                }
            })
            .collect();
        let channels = self
            .channels
            .values()
            .flat_map(|ownership| match ownership {
                ChannelOwnership::Owned(info) => vec![info.clone()],
                ChannelOwnership::Conflicted(infos) => infos.clone(),
            })
            .collect();
        (nicknames, channels)
    }

    /// Records that `nickname` was just registered locally, under
    /// `self_id` - called only after `is_registrable_here` allowed it.
    /// Goes through the same merge `merge_remote_nickname` does (rather
    /// than a bare overwrite) precisely so a peer's claim that raced in
    /// between the check and this call is never silently discarded: it
    /// becomes `Conflicted`, the same as if the order of arrival had been
    /// reversed.
    pub fn record_local_nickname(&mut self, nickname: String, self_id: &str) -> io::Result<()> {
        self.merge_remote_nickname(nickname, self_id.to_string())
    }

    /// Whether `nickname` may be freshly registered on `self_id` right
    /// now: unknown anywhere in the federation, or (harmlessly) already
    /// on `self_id` itself. `Err` names the reason - already owned by a
    /// peer, or in conflict - so the caller can hand it straight back as
    /// a `RegisterResult` reason.
    pub fn is_registrable_here(&self, nickname: &str, self_id: &str) -> Result<(), String> {
        match self.nicknames.get(nickname) {
            None => Ok(()),
            Some(Ownership::Owned(owner)) if owner == self_id => Ok(()),
            Some(Ownership::Owned(owner)) => Err(format!(
                "this nickname is registered on federated server '{owner}' - log in there instead"
            )),
            Some(Ownership::Conflicted(_)) => Err(
                "this nickname exists on multiple federated servers and needs administrator \
                 resolution"
                    .to_string(),
            ),
        }
    }

    /// Merges in a peer's claim that `nickname` belongs to `owner` -
    /// applied both to each entry of an incoming `DirectorySnapshot` and
    /// to a live `NicknameRegistered` gossip message (and, via
    /// `record_local_nickname`, to this server's own registrations too).
    /// Never refuses a *collision*: `Ownership::merge` is what turns a
    /// real one into `Conflicted` rather than silently picking a winner,
    /// whichever side of the race called it.
    ///
    /// It does refuse a name or owner that could not have been registered
    /// here in the first place, and that check is not cosmetic: these
    /// entries are persisted as `"{name}\t{spec}\n"`, with a conflict's
    /// claimants joined by `,`, so a peer gossiping a nickname containing
    /// a newline could write whole extra lines of its own choosing into
    /// this server's directory - marking any name it liked `Conflicted`,
    /// federation-wide and across restarts - and one containing a tab or a
    /// comma could forge the owner field. A peer is trusted to say who
    /// owns what; it is not trusted to write arbitrary bytes into a file
    /// this server parses on every start.
    pub fn merge_remote_nickname(&mut self, nickname: String, owner: String) -> io::Result<()> {
        self.merge_remote_nicknames(std::iter::once((nickname, owner)))
    }

    /// `merge_remote_nickname` for many at once, saving **once** at the
    /// end rather than per entry - what a `DirectorySnapshot` applies.
    ///
    /// The difference is not a micro-optimisation: each save rewrites the
    /// whole file, and the snapshot arm holds the directory lock across
    /// the loop, so per-entry saving made one link-up cost N full-file
    /// writes serialised against every login check and registration on
    /// this server. At a few hundred nicknames that is a visible stall; at
    /// tens of thousands it is minutes of disk and a locked-out server,
    /// reachable by an honest large federation and trivially forced by a
    /// peer sending a large snapshot.
    pub fn merge_remote_nicknames(
        &mut self,
        entries: impl IntoIterator<Item = (String, String)>,
    ) -> io::Result<()> {
        let mut changed = false;
        for (nickname, owner) in entries {
            if !crate::validation::nickname_is_registrable(&nickname) || !owner_id_is_storable(&owner) {
                continue;
            }
            self.nicknames
                .entry(nickname)
                .and_modify(|o| o.merge(&owner))
                .or_insert_with(|| Ownership::Owned(owner));
            changed = true;
        }
        if changed { self.save_nicknames() } else { Ok(()) }
    }

    /// Removes `owner`'s claim on `nickname` - the mirror of
    /// `merge_remote_nickname` for a `NicknameRemoved` gossip message (a
    /// superadmin's account removal). A `Conflicted` entry loses just
    /// that one claimant: downgraded back to `Owned` if exactly one
    /// remains, cleared entirely if none do, otherwise left `Conflicted`
    /// with the smaller list - so resolving a collision by removing one
    /// side doesn't require anything from the other side too. A message
    /// naming an owner that isn't actually a current claimant (a stale or
    /// malformed one) is a no-op.
    pub fn remove_nickname(&mut self, nickname: &str, owner: &str) -> io::Result<()> {
        let Some(existing) = self.nicknames.get_mut(nickname) else {
            return Ok(());
        };
        match existing {
            Ownership::Owned(o) if o == owner => {
                self.nicknames.remove(nickname);
            }
            Ownership::Owned(_) => {}
            Ownership::Conflicted(owners) => {
                owners.retain(|o| o != owner);
                match owners.len() {
                    0 => {
                        self.nicknames.remove(nickname);
                    }
                    1 => {
                        let remaining = owners.remove(0);
                        self.nicknames.insert(nickname.to_string(), Ownership::Owned(remaining));
                    }
                    _ => {}
                }
            }
        }
        self.save_nicknames()
    }

    /// Records that `info.name` was just created locally (`info.owner` is
    /// this server's own id) - goes through the same merge
    /// `merge_remote_channel` does, for the same race-closing reason
    /// `record_local_nickname` does.
    pub fn record_local_channel(&mut self, info: FederatedChannelInfo) {
        self.merge_remote_channel(info);
    }

    /// Merges in a peer's claim about `info.name` - same "never refuse,
    /// only ever escalate to a conflict marker" contract as
    /// `merge_remote_nickname`. A channel conflict has no automatic
    /// resolution (there is no existing session to keep working the way
    /// a conflicted nickname's already-connected clients stay connected):
    /// a `Conflicted` channel name simply isn't proxy-routable, and
    /// blocks a fresh creation of the same name, until an operator
    /// renames one side.
    /// A name or owner that could not have been created here is dropped,
    /// for the same reason `merge_remote_nickname` drops one: a peer says
    /// who owns what, it does not get to choose the bytes this server
    /// stores and shows. (The channel directory is in memory only, so
    /// there is no file to corrupt here - but a name no local client could
    /// ever type would be permanently unroutable and permanently listed,
    /// which is its own small denial of service.)
    pub fn merge_remote_channel(&mut self, info: FederatedChannelInfo) {
        if !crate::validation::channel_name_is_valid(&info.name) || !owner_id_is_storable(&info.owner) {
            return;
        }
        self.channels
            .entry(info.name.clone())
            .and_modify(|existing| merge_channel_entry(existing, info.clone()))
            .or_insert_with(|| ChannelOwnership::Owned(info));
    }

    /// Removes `owner`'s claim on channel `name` - the mirror of
    /// `merge_remote_channel` for a `ChannelRemoved` gossip message (this
    /// server's own `/delete-channel`, a superadmin's removal, or the
    /// inactivity sweep, relayed the same way regardless of which). Same
    /// partial-removal behaviour `remove_nickname` gives a `Conflicted`
    /// entry: only `owner`'s claim is dropped, not the whole entry.
    pub fn remove_channel(&mut self, name: &str, owner: &str) {
        let Some(existing) = self.channels.get_mut(name) else {
            return;
        };
        match existing {
            ChannelOwnership::Owned(info) if info.owner == owner => {
                self.channels.remove(name);
            }
            ChannelOwnership::Owned(_) => {}
            ChannelOwnership::Conflicted(owners) => {
                owners.retain(|o| o.owner != owner);
                match owners.len() {
                    0 => {
                        self.channels.remove(name);
                    }
                    1 => {
                        let remaining = owners.remove(0);
                        self.channels.insert(name.to_string(), ChannelOwnership::Owned(remaining));
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Whether a `server_federation_id` may be written into this directory as
/// an owner. Beyond `is_storable`'s tab/newline rule (this file is
/// tab-separated, one entry per line), a comma is refused too: a
/// `Conflicted` entry encodes its claimants as a comma-joined list, so an
/// id containing one would come back from disk as two different servers.
///
/// Checked on the way *in* from a peer (`merge_remote_nickname`,
/// `merge_remote_channel`) and on the way *out* of settings, where
/// `main.rs` refuses to start a server whose own id fails it - the peer
/// ids in `server_federation_peer` were already validated when parsed,
/// but a server's own `server_federation_id` never was.
pub fn owner_id_is_storable(owner: &str) -> bool {
    !owner.is_empty() && crate::validation::is_storable(owner) && !owner.contains(',')
}

fn encode_ownership(ownership: &Ownership) -> String {
    match ownership {
        Ownership::Owned(owner) => format!("owned:{owner}"),
        Ownership::Conflicted(owners) => format!("conflict:{}", owners.join(",")),
    }
}

fn parse_nicknames(contents: &str) -> HashMap<String, Ownership> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let Some((name, spec)) = line.split_once('\t') else {
            continue;
        };
        let ownership = if let Some(owner) = spec.strip_prefix("owned:") {
            if owner.is_empty() {
                continue;
            }
            Ownership::Owned(owner.to_string())
        } else if let Some(owners) = spec.strip_prefix("conflict:") {
            let owners: Vec<String> = owners.split(',').map(str::to_string).collect();
            if owners.is_empty() {
                continue;
            }
            Ownership::Conflicted(owners)
        } else {
            continue;
        };
        map.insert(name.to_string(), ownership);
    }
    map
}
