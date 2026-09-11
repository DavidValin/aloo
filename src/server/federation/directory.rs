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
}

impl FederationDirectory {
    /// Opens (creating if needed) the directory rooted at `dir`, loading
    /// whatever nickname ownership was persisted from a previous run. A
    /// missing or corrupt file starts empty rather than failing - the
    /// directory rebuilds from a peer's next `DirectorySnapshot` either
    /// way, so losing a stale copy is never fatal, only a brief window
    /// with less to check against.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let nicknames = std::fs::read_to_string(nicknames_path(&dir))
            .map(|contents| parse_nicknames(&contents))
            .unwrap_or_default();
        Ok(Self {
            nicknames,
            channels: HashMap::new(),
            dir,
        })
    }

    fn save_nicknames(&self) -> io::Result<()> {
        let mut lines: Vec<(&String, &Ownership)> = self.nicknames.iter().collect();
        lines.sort_by_key(|(name, _)| (*name).clone());
        let contents: String = lines
            .into_iter()
            .map(|(name, ownership)| format!("{name}\t{}\n", encode_ownership(ownership)))
            .collect();
        std::fs::write(nicknames_path(&self.dir), contents)
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
    /// Never refuses: `Ownership::merge` is what turns a real collision
    /// into `Conflicted` rather than silently picking a winner, whichever
    /// side of the race called it.
    pub fn merge_remote_nickname(&mut self, nickname: String, owner: String) -> io::Result<()> {
        self.nicknames
            .entry(nickname)
            .and_modify(|o| o.merge(&owner))
            .or_insert_with(|| Ownership::Owned(owner));
        self.save_nicknames()
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
    pub fn merge_remote_channel(&mut self, info: FederatedChannelInfo) {
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
