//! The channels registry: what channels exist, who is in them, and (per
//! the channel-ownership/moderation feature) who administers each one,
//! who is banned from it, whether joining it is currently locked to an
//! allowlist, and how long it may sit empty before it's swept away.
//!
//! Split out of `server::Registry` the same way `users_registry` already
//! is its own module. `Registry` keeps connection identity
//! (`clients`/`next_id`) and resolves a caller's `UserId` to a nickname -
//! or a target nickname to a `UserId`, via its own `id_by_name` - before
//! delegating in here: every admin/ban/lock decision below is keyed by
//! nickname, never `UserId`, because a `UserId` is never reused across a
//! reconnect (TB-020) and a per-`UserId` key would not survive even the
//! channel's own admin reconnecting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, ServerMessage, UserId, UserInfo};
use crate::server::federation::proto::RemoteIdentity;
use crate::validation;

use super::Outgoing;

/// The one channel `ChannelsRegistry::new()` always seeds and no deletion
/// path - an admin's `/delete-channel`, a superadmin's removal, or the
/// inactivity sweep - ever removes. Belongs to nobody: its `admin` is
/// always `None`.
pub const DEFAULT_CHANNEL_NAME: &str = "the-hall";

/// More than this many wrong-password attempts against one (source IP,
/// channel name) pair trips `CHANNEL_PASSWORD_BAN_DURATION`.
pub const CHANNEL_MAX_PASSWORD_ATTEMPTS: u32 = 7;
/// How long a brute-force ban (`CHANNEL_MAX_PASSWORD_ATTEMPTS`) lasts.
pub const CHANNEL_PASSWORD_BAN_DURATION: Duration = Duration::from_secs(2 * 60 * 60);

struct ChannelRecord {
    kind: ChannelKind,
    members: BTreeSet<UserId>,
    /// Set only for a private channel created with a non-empty password;
    /// `None` for a public channel (a password sent alongside
    /// `ChannelKind::Public` is silently ignored) or a private one created
    /// without one. Fixed at creation like `kind` - there is no message to
    /// change a channel's password afterward.
    password: Option<String>,
    /// The creator's nickname, carried forward by `/assign-admin`. `None`
    /// permanently for `DEFAULT_CHANNEL_NAME` only - it is seeded directly
    /// by `new()`, never created through `join`, so the "a genuinely new
    /// channel's creator becomes its admin" rule never applies to it.
    admin: Option<String>,
    /// Nicknames force-removed by `/ban`; enforced at join time going
    /// forward, cleared by `/unban`.
    banned: BTreeSet<String>,
    /// `None` = anyone may join (the default, and what `/lock-joins`'s
    /// "All users" option sets it back to). `Some(set)` = only these
    /// nicknames, plus the admin (always implicitly), may *join* from now
    /// on - an already-joined member who isn't on the list is unaffected
    /// either way, since this gates joining, not membership.
    join_lock: Option<BTreeSet<String>>,
    /// Bumped on every successful, non-rejoin join to this channel
    /// (including the creation-join) - the one "activity" signal the
    /// inactivity sweep can read, since the server never sees P2P
    /// channel-message content at all.
    last_join_at: Instant,
    /// Federation only (`crate::server::federation`): every remote member
    /// currently known to belong to this channel, keyed by (their
    /// server, their nickname). On the channel's *home* server this is
    /// authoritative - every (owning server, nickname) pair a join-proxy
    /// request has granted entry to - and never touches `members`, since
    /// there is no `UserId` for a connection to a different server. On a
    /// server that only *mirrors* this channel (joined via someone else's
    /// proxy, or learned of it from `ChannelRegistered`), it is instead a
    /// live copy of the home server's membership, kept current by
    /// `ChannelMemberJoined`/`ChannelMemberLeft` gossip - used purely for
    /// display (who's in the channel), never for password/ban/allowlist
    /// decisions, which only the home server ever makes.
    remote_members: BTreeMap<(String, String), RemoteIdentity>,
}

/// Brute-force tracking for one (source IP, channel name) pair's wrong
/// private-channel-password attempts (US-025).
struct PasswordAttemptRecord {
    /// Consecutive wrong attempts since the last reset (a successful join
    /// to this channel from this IP, or this record not existing yet).
    wrong_attempts: u32,
    /// Set once `wrong_attempts` exceeds `CHANNEL_MAX_PASSWORD_ATTEMPTS`;
    /// checked via `.elapsed() < CHANNEL_PASSWORD_BAN_DURATION`.
    banned_at: Option<Instant>,
}

/// A join turned down, in the one shape every refusal here takes: a
/// single `ChannelJoinRejected` back to whoever tried, naming the channel
/// they tried and which of `ChannelJoinRejection`'s reasons applied. All
/// five refusals in `join` differ only in that reason, and this is what
/// keeps them saying so and nothing else.
fn reject_join(id: UserId, name: &str, kind: ChannelJoinRejection) -> Vec<Outgoing> {
    vec![Outgoing::new(
        id,
        ServerMessage::ChannelJoinRejected {
            name: name.to_string(),
            kind,
        },
    )]
}

/// Pure channel bookkeeping - existence, kind, password, membership,
/// admin, bans, join-locks, and inactivity - with no connection identity
/// (that stays in `Registry`) and no I/O of its own. Every mutation
/// returns the list of messages that need to go out as a result, leaving
/// delivery to the async layer, exactly like `Registry` itself.
pub struct ChannelsRegistry {
    channels: HashMap<String, ChannelRecord>,
    /// In-memory only; lost on server restart, same as every channel
    /// itself.
    channel_password_attempts: HashMap<(IpAddr, String), PasswordAttemptRecord>,
    /// `server_channel_deletion_unactivity_period`. `None` means the
    /// inactivity sweep never runs, so channels persist while empty
    /// indefinitely - the same way `DEFAULT_CHANNEL_NAME` already does
    /// unconditionally.
    deletion_unactivity_period: Option<Duration>,
}

impl ChannelsRegistry {
    /// Starts with one default public channel, belonging to nobody, so a
    /// freshly started server always has somewhere for the first client
    /// to auto-join.
    pub fn new(deletion_unactivity_period: Option<Duration>) -> Self {
        let mut channels = HashMap::new();
        channels.insert(
            DEFAULT_CHANNEL_NAME.to_string(),
            ChannelRecord {
                kind: ChannelKind::Public,
                members: BTreeSet::new(),
                password: None,
                admin: None,
                banned: BTreeSet::new(),
                join_lock: None,
                last_join_at: Instant::now(),
                remote_members: BTreeMap::new(),
            },
        );
        Self {
            channels,
            channel_password_attempts: HashMap::new(),
            deletion_unactivity_period,
        }
    }

    /// Public channels only: private channels are only reachable by
    /// knowing their name (Ctrl+J), never advertised in the tab list.
    pub fn list(&self) -> Vec<ChannelInfo> {
        let mut v: Vec<ChannelInfo> = self
            .channels
            .iter()
            .filter(|(_, rec)| rec.kind == ChannelKind::Public)
            .map(|(name, rec)| ChannelInfo {
                name: name.clone(),
                kind: rec.kind,
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Whether `name` already exists, public or private - what
    /// `crate::server::mod`'s federation hook checks *before* calling
    /// `join` to tell "this created a new channel" apart from "this
    /// joined an existing one" without `join` itself needing to know
    /// anything about federation.
    pub fn contains(&self, name: &str) -> bool {
        self.channels.contains_key(name)
    }

    /// Joins `id` (whose own info is `joiner`) to `name`, creating the
    /// channel (as `kind`, with `joiner` becoming its admin) if needed;
    /// idempotent for a channel already joined. `user_info_of` resolves
    /// an existing member's `UserId` to their `UserInfo` (`Registry` is
    /// the only thing that can do this, since connection identity lives
    /// there); `all_client_ids` is every currently-connected `UserId`,
    /// needed only to broadcast a genuinely new public channel's creation.
    /// `remote_user_info` resolves a federated member's `RemoteIdentity`
    /// to a displayable `UserInfo` (a stable synthetic `UserId` minted for
    /// them, since there is no real connection here) - only used to tell
    /// `joiner` about members already present through federation; a
    /// remote member is never itself sent anything, having no connection
    /// to this server for it to arrive on.
    #[allow(clippy::too_many_arguments)]
    pub fn join(
        &mut self,
        id: UserId,
        joiner: &UserInfo,
        name: &str,
        kind: ChannelKind,
        password: Option<&str>,
        source_ip: IpAddr,
        allow_create_public_channels: bool,
        all_client_ids: &[UserId],
        user_info_of: impl Fn(UserId) -> Option<UserInfo>,
        mut remote_user_info: impl FnMut(&RemoteIdentity) -> UserInfo,
    ) -> Result<Vec<Outgoing>, String> {
        if !validation::channel_name_is_valid(name) {
            return Err(format!(
                "channel name must be 1-{} characters of letters, digits, '-' or '_'",
                validation::CHANNEL_NAME_MAX_LEN
            ));
        }
        if !self.channels.contains_key(name)
            && let Some(pw) = password
            && !validation::channel_password_is_valid(pw)
        {
            return Err(format!(
                "channel password must be at most {} characters of letters, digits, and the allowed symbols",
                validation::CHANNEL_PASSWORD_MAX_LEN
            ));
        }

        let existed_before = self.channels.contains_key(name);
        if !existed_before && kind == ChannelKind::Public && !allow_create_public_channels {
            return Err(
                "this server does not allow creating new public channels - join an \
                 existing one, or create a private channel instead"
                    .to_string(),
            );
        }

        let (existing_members, existing_remote_members, channel_kind, channel_password, already_member) = {
            let rec = self
                .channels
                .entry(name.to_string())
                .or_insert_with(|| ChannelRecord {
                    kind,
                    members: BTreeSet::new(),
                    password: match kind {
                        ChannelKind::Private => {
                            password.filter(|p| !p.is_empty()).map(str::to_owned)
                        }
                        ChannelKind::Public => None,
                    },
                    admin: Some(joiner.name.clone()),
                    banned: BTreeSet::new(),
                    join_lock: None,
                    last_join_at: Instant::now(),
                    remote_members: BTreeMap::new(),
                });
            let existing: Vec<UserId> = rec.members.iter().copied().collect();
            let existing_remote: Vec<RemoteIdentity> = rec.remote_members.values().cloned().collect();
            let already = rec.members.contains(&id);
            (existing, existing_remote, rec.kind, rec.password.clone(), already)
        };

        // A moderation ban and an allowlist lock are checked before the
        // password logic - they exist for a different reason (who's
        // welcome at all, decided by the admin) than the brute-force
        // protection below (is this really the password's owner), and an
        // already-joined member is exempt from both: this only gates
        // joining, never membership already held.
        if !already_member {
            let rec = self.channels.get(name).expect("just looked up above");
            if let Err(rejection) = Self::ban_and_allowlist_check(rec, &joiner.name) {
                return Ok(reject_join(id, name, rejection));
            }
        }

        if !already_member
            && let Some(expected) = &channel_password
            && let Err(rejection) = self.password_check(name, expected, password, source_ip)
        {
            return Ok(reject_join(id, name, rejection));
        }

        if already_member {
            return Ok(Vec::new());
        }
        {
            let rec = self.channels.get_mut(name).expect("just looked up above");
            rec.members.insert(id);
            rec.last_join_at = Instant::now();
        }
        let admin = self.channels.get(name).and_then(|rec| rec.admin.clone());

        let mut outgoing = Vec::new();
        for member_id in existing_members {
            if let Some(info) = user_info_of(member_id) {
                outgoing.push(Outgoing::new(
                    id,
                    ServerMessage::UserJoined {
                        channel: name.to_string(),
                        user: info,
                    },
                ));
            }
            outgoing.push(Outgoing::new(
                member_id,
                ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: joiner.clone(),
                },
            ));
        }
        // Federated members are told about `joiner` by their own home
        // server's `ChannelMemberJoined` gossip, not here (there is no
        // connection to this server for them to receive it on) - but
        // `joiner` still needs to be told about *them*, or they would
        // simply not appear in a channel they are genuinely already in.
        for identity in &existing_remote_members {
            outgoing.push(Outgoing::new(
                id,
                ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: remote_user_info(identity),
                },
            ));
        }
        outgoing.push(Outgoing::new(
            id,
            ServerMessage::Joined {
                channel: ChannelInfo {
                    name: name.to_string(),
                    kind: channel_kind,
                },
                admin,
            },
        ));

        // A brand-new *public* channel is announced to every other client -
        // the one-time ChannelList snapshot at connect otherwise never
        // updates, so this is the only way anyone learns it exists.
        // A private channel stays unadvertised; the joiner already has
        // `Joined` above.
        if !existed_before && channel_kind == ChannelKind::Public {
            for &other_id in all_client_ids {
                if other_id != id {
                    outgoing.push(Outgoing::new(
                        other_id,
                        ServerMessage::ChannelCreated {
                            channel: ChannelInfo {
                                name: name.to_string(),
                                kind: channel_kind,
                            },
                        },
                    ));
                }
            }
        }

        Ok(outgoing)
    }

    /// The ban/allowlist gate: banned by nickname, or a join-lock this
    /// nickname isn't on (the admin is always implicitly exempt from
    /// their own lock). Shared by `join` (a local member, keyed by
    /// `UserId` everywhere else) and `join_remote` (a federation peer's
    /// member, which has no `UserId` at all) - both actually gate on the
    /// nickname, never the connection.
    fn ban_and_allowlist_check(rec: &ChannelRecord, joiner_name: &str) -> Result<(), ChannelJoinRejection> {
        if rec.banned.contains(joiner_name) {
            return Err(ChannelJoinRejection::UserBanned);
        }
        if let Some(allowed) = &rec.join_lock
            && rec.admin.as_deref() != Some(joiner_name)
            && !allowed.contains(joiner_name)
        {
            return Err(ChannelJoinRejection::NotOnAllowlist);
        }
        Ok(())
    }

    /// The password gate: the brute-force ban first, then the comparison
    /// itself, incrementing `channel_password_attempts` on a wrong one -
    /// shared with `join_remote` for the same reason
    /// `ban_and_allowlist_check` is.
    fn password_check(
        &mut self,
        name: &str,
        expected: &str,
        given: Option<&str>,
        source_ip: IpAddr,
    ) -> Result<(), ChannelJoinRejection> {
        let attempt_key = (source_ip, name.to_string());
        let banned = self
            .channel_password_attempts
            .get(&attempt_key)
            .and_then(|rec| rec.banned_at)
            .is_some_and(|t| t.elapsed() < CHANNEL_PASSWORD_BAN_DURATION);
        if banned {
            return Err(ChannelJoinRejection::Banned);
        }
        match given {
            None => Err(ChannelJoinRejection::PasswordRequired),
            Some(given) if !crypto::constant_time_eq(expected.as_bytes(), given.as_bytes()) => {
                let rec = self
                    .channel_password_attempts
                    .entry(attempt_key)
                    .or_insert_with(|| PasswordAttemptRecord {
                        wrong_attempts: 0,
                        banned_at: None,
                    });
                rec.wrong_attempts += 1;
                Err(if rec.wrong_attempts > CHANNEL_MAX_PASSWORD_ATTEMPTS {
                    rec.banned_at = Some(Instant::now());
                    ChannelJoinRejection::Banned
                } else {
                    ChannelJoinRejection::WrongPassword
                })
            }
            Some(_) => {
                self.channel_password_attempts.remove(&attempt_key);
                Ok(())
            }
        }
    }

    /// A federation peer's join-proxy request for `name`, which this
    /// server owns (`crate::server::federation`): the same ban/allowlist/
    /// password gates `join` applies to a local member, applied to
    /// `identity.nickname` (a client connected to `identity.server`, not
    /// here) instead. Records the join in `remote_members` on success -
    /// never `members`, since there is no `UserId` for a connection to a
    /// different server - and never stores or exposes the password
    /// itself beyond comparing against it. `None` if this server doesn't
    /// actually have `name` at all (a stale federation directory entry);
    /// the caller answers with `JoinProxyOutcome::UnknownChannel`.
    ///
    /// Also returns the `UserJoined` notices this channel's *existing
    /// local* members need - the caller (`crate::server::federation`)
    /// dispatches them and, on success, gossips `ChannelMemberJoined` to
    /// every other linked peer so servers with no local members here yet
    /// still learn who's in it, `user_info_of` resolves an existing
    /// member's `UserId` to their `UserInfo`, same as `join`.
    pub fn join_remote(
        &mut self,
        name: &str,
        identity: &RemoteIdentity,
        password: Option<&str>,
        source_ip: IpAddr,
        user_info_of: impl Fn(UserId) -> Option<UserInfo>,
        mut remote_user_info: impl FnMut(&RemoteIdentity) -> UserInfo,
    ) -> Option<Result<(ChannelKind, Option<String>, Vec<Outgoing>), ChannelJoinRejection>> {
        if !self.channels.contains_key(name) {
            return None;
        }
        let member_key = (identity.server.clone(), identity.nickname.clone());
        let (channel_password, already_member) = {
            let rec = self.channels.get(name).expect("checked above");
            (rec.password.clone(), rec.remote_members.contains_key(&member_key))
        };
        // Checked even for a member already recorded, unlike `join`'s own
        // "this gates joining, not membership already held" exemption. A
        // local member is force-removed by `ban` the instant it is issued,
        // so exempting them there is moot; a federated member's entry is
        // bookkeeping about a connection this server does not hold, and if
        // it ever outlives the ban's reach - a `LeaveProxyNotice` lost
        // while the link was down, say - the exemption is precisely what
        // would wave a banned nickname back in.
        {
            let rec = self.channels.get(name).expect("checked above");
            if let Err(rejection) = Self::ban_and_allowlist_check(rec, &identity.nickname) {
                return Some(Err(rejection));
            }
        }
        if !already_member
            && let Some(expected) = &channel_password
            && let Err(rejection) = self.password_check(name, expected, password, source_ip)
        {
            return Some(Err(rejection));
        }
        if already_member {
            let rec = self.channels.get(name).expect("checked above");
            return Some(Ok((rec.kind, rec.admin.clone(), Vec::new())));
        }
        let existing_members: Vec<UserId> = {
            let rec = self.channels.get(name).expect("checked above");
            rec.members.iter().copied().collect()
        };
        let rec = self.channels.get_mut(name).expect("checked above");
        rec.remote_members.insert(member_key, identity.clone());
        rec.last_join_at = Instant::now();
        let (kind, admin) = (rec.kind, rec.admin.clone());
        let joiner_info = remote_user_info(identity);
        let outgoing = existing_members
            .into_iter()
            .filter_map(|member_id| {
                user_info_of(member_id).map(|_| {
                    Outgoing::new(
                        member_id,
                        ServerMessage::UserJoined { channel: name.to_string(), user: joiner_info.clone() },
                    )
                })
            })
            .collect();
        Some(Ok((kind, admin, outgoing)))
    }

    /// The federation mirror of `leave`: removes `(remote_server,
    /// nickname)` from `name`'s `remote_members`, returning the `UserLeft`
    /// notices this channel's existing local members need (the caller
    /// gossips `ChannelMemberLeft` on to every other linked peer). A
    /// no-op for a channel that doesn't exist or wasn't a member - this
    /// only ever runs on the *home* server, in response to a best-effort
    /// `LeaveProxyNotice` that nothing else waits on. `remote_user_id`
    /// resolves the leaving member to the same synthetic `UserId` their
    /// `UserJoined` used, so a client's own member list stays consistent.
    pub fn leave_remote(
        &mut self,
        name: &str,
        remote_server: &str,
        nickname: &str,
        mut remote_user_id: impl FnMut(&str, &str) -> UserId,
    ) -> Vec<Outgoing> {
        let Some(rec) = self.channels.get_mut(name) else {
            return Vec::new();
        };
        if rec.remote_members.remove(&(remote_server.to_string(), nickname.to_string())).is_none() {
            return Vec::new();
        }
        let leaving_id = remote_user_id(remote_server, nickname);
        rec.members
            .iter()
            .map(|&member_id| {
                Outgoing::new(
                    member_id,
                    ServerMessage::UserLeft { channel: name.to_string(), user_id: leaving_id },
                )
            })
            .collect()
    }

    /// After a federation join-proxy grants `id` (whose own info is
    /// `joiner`) entry to `name` - owned by a different federated server,
    /// as the `kind`/`admin` that server reported - mirrors it locally so
    /// this server's own membership bookkeeping, and any other *local*
    /// client who also joins the same remote-homed channel, work exactly
    /// like an ordinary local channel: they get real `UserJoined`
    /// broadcasts and can punch a real direct link to each other, since
    /// both are genuinely connected here. Idempotent for a channel `id`
    /// already mirrors. Never stores a password - there is none to store;
    /// only the home server ever checks one.
    pub fn mirror_remote_join(
        &mut self,
        id: UserId,
        joiner: &UserInfo,
        name: &str,
        kind: ChannelKind,
        admin: Option<String>,
        user_info_of: impl Fn(UserId) -> Option<UserInfo>,
        mut remote_user_info: impl FnMut(&RemoteIdentity) -> UserInfo,
    ) -> Vec<Outgoing> {
        let existing_members: Vec<UserId> = self
            .channels
            .get(name)
            .map(|rec| rec.members.iter().copied().collect())
            .unwrap_or_default();
        let rec = self.channels.entry(name.to_string()).or_insert_with(|| ChannelRecord {
            kind,
            members: BTreeSet::new(),
            password: None,
            admin: admin.clone(),
            banned: BTreeSet::new(),
            join_lock: None,
            last_join_at: Instant::now(),
            remote_members: BTreeMap::new(),
        });
        // A channel that only "fully shared list" visibility
        // (`ensure_public_mirror`) had created ahead of time has no real
        // `kind`/`admin` yet - this join is the first time either is
        // actually known, so it corrects the stub rather than leaving it
        // permanently `admin: None`.
        rec.kind = kind;
        rec.admin = admin.clone();
        if rec.members.contains(&id) {
            return vec![Outgoing::new(
                id,
                ServerMessage::Joined {
                    channel: ChannelInfo {
                        name: name.to_string(),
                        kind: rec.kind,
                    },
                    admin: rec.admin.clone(),
                },
            )];
        }
        let existing_remote_members: Vec<RemoteIdentity> = rec.remote_members.values().cloned().collect();
        rec.members.insert(id);
        rec.last_join_at = Instant::now();
        let channel_kind = rec.kind;
        let admin = rec.admin.clone();

        let mut outgoing = Vec::new();
        for member_id in existing_members {
            if let Some(info) = user_info_of(member_id) {
                outgoing.push(Outgoing::new(
                    id,
                    ServerMessage::UserJoined {
                        channel: name.to_string(),
                        user: info,
                    },
                ));
            }
            outgoing.push(Outgoing::new(
                member_id,
                ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: joiner.clone(),
                },
            ));
        }
        for identity in &existing_remote_members {
            outgoing.push(Outgoing::new(
                id,
                ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: remote_user_info(identity),
                },
            ));
        }
        outgoing.push(Outgoing::new(
            id,
            ServerMessage::Joined {
                channel: ChannelInfo {
                    name: name.to_string(),
                    kind: channel_kind,
                },
                admin,
            },
        ));
        outgoing
    }

    /// Applies third-party `ChannelMemberJoined` gossip: `channel`'s home
    /// server (never this one - see `join_remote`, which is what runs
    /// there instead) says `identity` just joined. A no-op, silently
    /// dropped, for a channel this server has no local record of at all
    /// (nothing here to update, nobody local to tell); otherwise records
    /// `identity` in `remote_members` and tells this server's own local
    /// members about the new arrival, exactly like `join`'s existing
    /// members are told about a new joiner. Idempotent for a member
    /// already recorded (a repeat gossip after a reconnect, say).
    pub fn mirror_member_joined(
        &mut self,
        channel: &str,
        identity: &RemoteIdentity,
        mut remote_user_info: impl FnMut(&RemoteIdentity) -> UserInfo,
    ) -> Vec<Outgoing> {
        let Some(rec) = self.channels.get_mut(channel) else {
            return Vec::new();
        };
        let key = (identity.server.clone(), identity.nickname.clone());
        if rec.remote_members.contains_key(&key) {
            rec.remote_members.insert(key, identity.clone());
            return Vec::new();
        }
        rec.remote_members.insert(key, identity.clone());
        let user = remote_user_info(identity);
        rec.members
            .iter()
            .map(|&member_id| {
                Outgoing::new(member_id, ServerMessage::UserJoined { channel: channel.to_string(), user: user.clone() })
            })
            .collect()
    }

    /// The departure mirror of `mirror_member_joined`, for `ChannelMemberLeft`
    /// gossip. Same no-op/idempotency shape.
    pub fn mirror_member_left(
        &mut self,
        channel: &str,
        server: &str,
        nickname: &str,
        mut remote_user_id: impl FnMut(&str, &str) -> UserId,
    ) -> Vec<Outgoing> {
        let Some(rec) = self.channels.get_mut(channel) else {
            return Vec::new();
        };
        if rec.remote_members.remove(&(server.to_string(), nickname.to_string())).is_none() {
            return Vec::new();
        }
        let leaving_id = remote_user_id(server, nickname);
        rec.members
            .iter()
            .map(|&member_id| {
                Outgoing::new(member_id, ServerMessage::UserLeft { channel: channel.to_string(), user_id: leaving_id })
            })
            .collect()
    }

    /// Whether local member `id` and the federated member `(server,
    /// nickname)` are both in at least one of the same channels.
    ///
    /// This is the gate on relaying anything between two clients on
    /// different servers (`FederationMessage::PeerSignal`). Without it,
    /// asking for a link would be a way to make any client on any
    /// federated server hand its candidate addresses - its actual IPs - to
    /// a complete stranger, just by naming them. Sharing a channel is
    /// already the condition under which two clients on *one* server
    /// exchange those addresses, so this asks no more than the local case
    /// does; it just does not take the requester's word for it.
    pub fn share_a_channel(&self, id: UserId, server: &str, nickname: &str) -> bool {
        let key = (server.to_string(), nickname.to_string());
        self.channels
            .values()
            .any(|rec| rec.members.contains(&id) && rec.remote_members.contains_key(&key))
    }

    /// Everyone currently in `channel`, as the federation sees them: this
    /// server's own local members (named under `self_id`, their identity
    /// resolved through `user_info_of`) plus every federated member it has
    /// recorded. What the channel's *home* server sends a peer whose link
    /// has just come up (`FederationMessage::ChannelMembership`); empty,
    /// and so not worth sending, for a channel nobody is in.
    pub fn federated_membership_of(
        &self,
        channel: &str,
        self_id: &str,
        user_info_of: impl Fn(UserId) -> Option<UserInfo>,
    ) -> Vec<RemoteIdentity> {
        let Some(rec) = self.channels.get(channel) else {
            return Vec::new();
        };
        let local = rec.members.iter().filter_map(|&id| {
            user_info_of(id).map(|info| RemoteIdentity {
                server: self_id.to_string(),
                nickname: info.name,
                public_key_der: info.public_key_der,
                key_mode: info.key_mode,
            })
        });
        local.chain(rec.remote_members.values().cloned()).collect()
    }

    /// Replaces everything this server believes about who is in `channel`
    /// from elsewhere with `members`, the authoritative list its home
    /// server just sent, and tells this server's own local members about
    /// every difference: a `UserJoined` for anyone newly present, a
    /// `UserLeft` for anyone no longer there.
    ///
    /// Entries naming `self_id` are skipped: those are this server's own
    /// clients, who live in `members` as real connections and are never
    /// mirrored. A channel this server has no record of at all is left
    /// alone - nothing local to correct, nobody local to tell.
    pub fn replace_mirrored_members(
        &mut self,
        channel: &str,
        self_id: &str,
        members: Vec<RemoteIdentity>,
        mut remote_user_info: impl FnMut(&RemoteIdentity) -> UserInfo,
    ) -> Vec<Outgoing> {
        let Some(rec) = self.channels.get_mut(channel) else {
            return Vec::new();
        };
        let incoming: BTreeMap<(String, String), RemoteIdentity> = members
            .into_iter()
            .filter(|identity| identity.server != self_id)
            .map(|identity| ((identity.server.clone(), identity.nickname.clone()), identity))
            .collect();
        // Departing members are taken by *value*, not by key, so the
        // `UserLeft` below can be given the same id their `UserJoined`
        // used - resolved through the one identity-to-id mapping, rather
        // than a second closure borrowing the same mint state.
        let gone: Vec<RemoteIdentity> = rec
            .remote_members
            .iter()
            .filter(|(key, _)| !incoming.contains_key(*key))
            .map(|(_, identity)| identity.clone())
            .collect();
        let arrived: Vec<RemoteIdentity> = incoming
            .iter()
            .filter(|(key, _)| !rec.remote_members.contains_key(*key))
            .map(|(_, identity)| identity.clone())
            .collect();
        rec.remote_members = incoming;
        if gone.is_empty() && arrived.is_empty() {
            return Vec::new();
        }
        let local_members: Vec<UserId> = rec.members.iter().copied().collect();
        let mut outgoing = Vec::new();
        for identity in &gone {
            let left_id = remote_user_info(identity).id;
            for &to in &local_members {
                outgoing.push(Outgoing::new(
                    to,
                    ServerMessage::UserLeft { channel: channel.to_string(), user_id: left_id },
                ));
            }
        }
        for identity in &arrived {
            let user = remote_user_info(identity);
            for &to in &local_members {
                outgoing.push(Outgoing::new(
                    to,
                    ServerMessage::UserJoined { channel: channel.to_string(), user: user.clone() },
                ));
            }
        }
        outgoing
    }

    /// Drops every federated member belonging to `server` from every
    /// channel, telling this server's own local members they left - what
    /// runs when that peer's link goes down.
    ///
    /// Presence gossip is live-only: a `ChannelMemberLeft` that would have
    /// arrived while the link was down is simply never sent again, and
    /// nothing re-derives membership on reconnect. Without this, a peer
    /// crashing (or its clients disconnecting while it is unreachable)
    /// leaves its members listed here forever - visible in the member
    /// list, impossible to remove, and, since `sweep_inactive` counts
    /// `remote_members` as activity, holding the channel alive
    /// indefinitely. Forgetting them the moment the link drops is the
    /// honest reading: with no link to that server, this server genuinely
    /// does not know who over there is still in the channel. They come
    /// back with the next `ChannelMemberJoined`.
    pub fn forget_members_of_server(
        &mut self,
        server: &str,
        mut remote_user_id: impl FnMut(&str, &str) -> UserId,
    ) -> Vec<Outgoing> {
        let mut outgoing = Vec::new();
        for (channel, rec) in self.channels.iter_mut() {
            let departing: Vec<(String, String)> = rec
                .remote_members
                .keys()
                .filter(|(member_server, _)| member_server == server)
                .cloned()
                .collect();
            for key in departing {
                rec.remote_members.remove(&key);
                let leaving_id = remote_user_id(&key.0, &key.1);
                for &member_id in rec.members.iter() {
                    outgoing.push(Outgoing::new(
                        member_id,
                        ServerMessage::UserLeft { channel: channel.clone(), user_id: leaving_id },
                    ));
                }
            }
        }
        outgoing
    }

    /// "Fully shared channel list" (docs/PROTOCOL.md §18.2): ensures a
    /// *public* federated channel this server has just learned about
    /// (`ChannelRegistered` gossip or a `DirectorySnapshot`, never a
    /// private one - those stay unadvertised, reachable only by knowing
    /// their name) has a local stub entry, empty of members, so it shows
    /// up in this server's own `list()`/`ChannelList` immediately rather
    /// than only once some local client has joined it. Returns whether it
    /// was newly created - the caller uses that to decide whether to
    /// announce `ServerMessage::ChannelCreated` to already-connected local
    /// clients (a no-op if it was already known, whether as this server's
    /// own channel, a channel a local client had already joined via
    /// proxy, or a previous run of this same method).
    pub fn ensure_public_mirror(&mut self, name: &str, kind: ChannelKind) -> bool {
        if kind != ChannelKind::Public || self.channels.contains_key(name) {
            return false;
        }
        self.channels.insert(
            name.to_string(),
            ChannelRecord {
                kind,
                members: BTreeSet::new(),
                password: None,
                admin: None,
                banned: BTreeSet::new(),
                join_lock: None,
                last_join_at: Instant::now(),
                remote_members: BTreeMap::new(),
            },
        );
        true
    }

    /// Every channel `id` currently belongs to - read-only, used to
    /// notify a federation home server of a departure before removal
    /// actually happens (`crate::server::mod`'s `LeaveChannel`/disconnect
    /// handling).
    pub fn member_of(&self, id: UserId) -> Vec<String> {
        self.channels
            .iter()
            .filter(|(_, rec)| rec.members.contains(&id))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Removes `id` from `name`'s membership, if it was a member - a
    /// no-op, returning nothing, if `name` doesn't exist or `id` wasn't a
    /// member. Unlike before this feature existed, an emptied channel is
    /// *not* deleted here; see `sweep_inactive` for how (and whether)
    /// that now happens. Shared by `leave` (`UserLeft`), `remove_from_all`
    /// (`UserOffline`), and `ban` (a forced single-channel removal).
    fn remove_member(&mut self, id: UserId, name: &str) -> Vec<UserId> {
        let Some(rec) = self.channels.get_mut(name) else {
            return Vec::new();
        };
        if !rec.members.remove(&id) {
            return Vec::new();
        }
        rec.members.iter().copied().collect()
    }

    /// Removes `id` from `name`, notifying remaining members.
    pub fn leave(&mut self, id: UserId, name: &str) -> Vec<Outgoing> {
        self.remove_member(id, name)
            .into_iter()
            .map(|member_id| {
                Outgoing::new(
                    member_id,
                    ServerMessage::UserLeft {
                        channel: name.to_string(),
                        user_id: id,
                    },
                )
            })
            .collect()
    }

    /// Removes `id` from every channel it was in (on disconnect). Peers
    /// who shared *any* channel with `id` get exactly one `UserOffline`
    /// each, no matter how many channels they shared.
    pub fn remove_from_all(&mut self, id: UserId) -> Vec<Outgoing> {
        let channel_names: Vec<String> = self
            .channels
            .iter()
            .filter(|(_, rec)| rec.members.contains(&id))
            .map(|(name, _)| name.clone())
            .collect();
        let mut recipients: BTreeSet<UserId> = BTreeSet::new();
        for name in &channel_names {
            recipients.extend(self.remove_member(id, name));
        }
        recipients
            .into_iter()
            .map(|to| Outgoing::new(to, ServerMessage::UserOffline { user_id: id }))
            .collect()
    }

    pub fn is_member(&self, channel: &str, id: UserId) -> bool {
        self.channels
            .get(channel)
            .is_some_and(|rec| rec.members.contains(&id))
    }

    /// Common gate for `/delete-channel`, `/ban`, `/unban`,
    /// `/lock-joins`, `/assign-admin`: refuses a channel that doesn't
    /// exist, one with no admin (`DEFAULT_CHANNEL_NAME` alone - it
    /// belongs to nobody, on purpose), or a caller who isn't its current
    /// admin.
    fn require_caller_is_admin(
        &mut self,
        name: &str,
        caller_name: &str,
    ) -> Result<&mut ChannelRecord, String> {
        let rec = self
            .channels
            .get_mut(name)
            .ok_or_else(|| format!("no such channel: {name}"))?;
        match &rec.admin {
            None => Err(format!("{name} has no admin")),
            Some(admin) if admin != caller_name => {
                Err("only this channel's admin may do that".to_string())
            }
            Some(_) => Ok(rec),
        }
    }

    /// Removes `name` outright - never `DEFAULT_CHANNEL_NAME`, which is
    /// exempt from every deletion path, admin-triggered or
    /// superadmin-triggered alike - notifying every current member with
    /// `reason`. A no-op, returning nothing, if `name` doesn't exist.
    pub fn force_delete_channel(&mut self, name: &str, reason: String) -> Vec<Outgoing> {
        if name == DEFAULT_CHANNEL_NAME {
            return Vec::new();
        }
        let Some(rec) = self.channels.remove(name) else {
            return Vec::new();
        };
        rec.members
            .into_iter()
            .map(|to| {
                Outgoing::new(
                    to,
                    ServerMessage::ChannelRemoved {
                        name: name.to_string(),
                        reason: reason.clone(),
                    },
                )
            })
            .collect()
    }

    /// `/delete-channel`: admin-only, and only for a public channel -
    /// recreating it fresh is just its next ordinary `join`.
    pub fn delete_channel(&mut self, caller_name: &str, name: &str) -> Result<Vec<Outgoing>, String> {
        let rec = self.require_caller_is_admin(name, caller_name)?;
        if rec.kind != ChannelKind::Public {
            return Err("/delete-channel only works on public channels".to_string());
        }
        Ok(self.force_delete_channel(name, "deleted by its admin".to_string()))
    }

    /// `/ban <nickname>`: admin-only, any channel kind. Force-removes
    /// `target_nickname` from `channel` if `target_id` names a current
    /// member, notifying everyone who was a member (the banned person
    /// included, so a live client can tell the two cases apart by
    /// comparing `user_id` to its own). Future joins by `target_nickname`
    /// are refused going forward regardless of whether they were ever a
    /// member at all. A federated member holding that nickname is removed
    /// too - the returned `(server, nickname)` pairs are who, so the
    /// caller can gossip a `ChannelMemberLeft` for each and every other
    /// server stops showing them in this channel.
    pub fn ban(
        &mut self,
        caller_name: &str,
        channel: &str,
        target_nickname: &str,
        target_id: Option<UserId>,
        mut remote_user_id: impl FnMut(&str, &str) -> UserId,
    ) -> Result<(Vec<Outgoing>, Vec<(String, String)>), String> {
        let rec = self.require_caller_is_admin(channel, caller_name)?;
        rec.banned.insert(target_nickname.to_string());
        // A federated member holding this nickname is force-removed too,
        // exactly as a local one is below. Without this a ban is simply
        // unenforceable against anyone connected through another server:
        // `target_id` comes from `Registry::id_by_name`, which only knows
        // *local* connections, so the nickname would land in `banned`
        // while its owner stayed in `remote_members` - and since a
        // `join_remote` for an entry already there used to skip the ban
        // check, every later proxy-join for them would sail through it.
        let banned_federated: Vec<(String, String)> = rec
            .remote_members
            .keys()
            .filter(|(_, nickname)| nickname == target_nickname)
            .cloned()
            .collect();
        for key in &banned_federated {
            rec.remote_members.remove(key);
        }
        let local_members: Vec<UserId> = rec.members.iter().copied().collect();
        let mut out = Vec::new();
        for (server, nickname) in &banned_federated {
            let banned_id = remote_user_id(server, nickname);
            for &to in &local_members {
                out.push(Outgoing::new(
                    to,
                    ServerMessage::UserBanned {
                        channel: channel.to_string(),
                        user_id: banned_id,
                        nickname: nickname.clone(),
                    },
                ));
            }
        }
        if let Some(id) = target_id.filter(|id| self.channels[channel].members.contains(id)) {
            let remaining = self.remove_member(id, channel);
            for to in remaining.into_iter().chain(std::iter::once(id)) {
                out.push(Outgoing::new(
                    to,
                    ServerMessage::UserBanned {
                        channel: channel.to_string(),
                        user_id: id,
                        nickname: target_nickname.to_string(),
                    },
                ));
            }
        }
        Ok((out, banned_federated))
    }

    /// `/unban <nickname>`: admin-only. Only reverses the ban itself - the
    /// nickname must rejoin, which will now succeed.
    pub fn unban(
        &mut self,
        caller_name: &str,
        channel: &str,
        target_nickname: &str,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.require_caller_is_admin(channel, caller_name)?;
        rec.banned.remove(target_nickname);
        Ok(rec
            .members
            .iter()
            .map(|&to| {
                Outgoing::new(
                    to,
                    ServerMessage::UserUnbanned {
                        channel: channel.to_string(),
                        nickname: target_nickname.to_string(),
                    },
                )
            })
            .collect())
    }

    /// `/lock-joins`: admin-only. `allowed: None` is "All users" - clears
    /// the lock entirely. Gates future joins only; a currently-joined
    /// member left off a narrower list is not removed.
    pub fn set_join_lock(
        &mut self,
        caller_name: &str,
        channel: &str,
        allowed: Option<Vec<String>>,
    ) -> Result<Vec<Outgoing>, String> {
        if let Some(names) = &allowed {
            for n in names {
                if !validation::nickname_is_registrable(n) {
                    return Err(format!("{n:?} is not a valid nickname"));
                }
            }
        }
        let rec = self.require_caller_is_admin(channel, caller_name)?;
        rec.join_lock = allowed.map(|v| v.into_iter().collect());
        Ok(rec
            .members
            .iter()
            .map(|&to| {
                Outgoing::new(
                    to,
                    ServerMessage::ChannelJoinLockUpdated {
                        channel: channel.to_string(),
                        by: caller_name.to_string(),
                    },
                )
            })
            .collect())
    }

    /// `/assign-admin <nickname>`: admin-only, and only onto a current
    /// member (`target_is_member`, resolved by `Registry` since it needs
    /// the nickname-to-`UserId` map this module doesn't have) - releases
    /// the caller's own admin status in the same stroke, since a channel
    /// has exactly one admin at a time.
    pub fn assign_admin(
        &mut self,
        caller_name: &str,
        channel: &str,
        target_nickname: &str,
        target_is_member: bool,
    ) -> Result<Vec<Outgoing>, String> {
        if !target_is_member {
            return Err(format!("{target_nickname} must be a member of {channel} first"));
        }
        let rec = self.require_caller_is_admin(channel, caller_name)?;
        rec.admin = Some(target_nickname.to_string());
        Ok(rec
            .members
            .iter()
            .map(|&to| {
                Outgoing::new(
                    to,
                    ServerMessage::ChannelAdminChanged {
                        channel: channel.to_string(),
                        admin: Some(target_nickname.to_string()),
                    },
                )
            })
            .collect())
    }

    /// Every channel `nickname` currently administers - never
    /// `DEFAULT_CHANNEL_NAME`, whose admin is always `None` and so is
    /// automatically excluded. Drives a superadmin's account-removal
    /// cascade.
    pub fn channels_administered_by(&self, nickname: &str) -> Vec<String> {
        self.channels
            .iter()
            .filter(|(_, rec)| rec.admin.as_deref() == Some(nickname))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Destroys every channel (other than `DEFAULT_CHANNEL_NAME`, always
    /// exempt) that currently has zero members *and* hasn't had a
    /// successful join in at least `deletion_unactivity_period` - a
    /// no-op when that isn't configured. Join events, not messages, are
    /// the "activity" measured: the server never sees P2P channel
    /// content, so a channel that still has members is never a candidate
    /// regardless of how long ago the last join into it was.
    /// Returns the names actually removed, so a federation-enabled server
    /// can gossip each one's departure (`crate::server::mod`'s
    /// `channel_sweep_loop`) - empty whenever nothing was due, including
    /// when no period is configured at all.
    pub(crate) fn sweep_inactive(&mut self) -> Vec<String> {
        let Some(period) = self.deletion_unactivity_period else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        self.channels.retain(|name, rec| {
            // `remote_members` matters here exactly as much as `members`:
            // a channel this server is home to can have every one of its
            // members connected through other federated servers, and a
            // channel this server only mirrors can likewise have real
            // (federated) presence with zero local members - neither is
            // "inactive" just because nobody local is in it.
            let keep = name == DEFAULT_CHANNEL_NAME
                || !rec.members.is_empty()
                || !rec.remote_members.is_empty()
                || rec.last_join_at.elapsed() < period;
            if !keep {
                removed.push(name.clone());
            }
            keep
        });
        removed
    }
}
