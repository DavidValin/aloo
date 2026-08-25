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

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, ServerMessage, UserId, UserInfo};
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

    /// Joins `id` (whose own info is `joiner`) to `name`, creating the
    /// channel (as `kind`, with `joiner` becoming its admin) if needed;
    /// idempotent for a channel already joined. `user_info_of` resolves
    /// an existing member's `UserId` to their `UserInfo` (`Registry` is
    /// the only thing that can do this, since connection identity lives
    /// there); `all_client_ids` is every currently-connected `UserId`,
    /// needed only to broadcast a genuinely new public channel's creation.
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

        let (existing_members, channel_kind, channel_password, already_member) = {
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
                });
            let existing: Vec<UserId> = rec.members.iter().copied().collect();
            let already = rec.members.contains(&id);
            (existing, rec.kind, rec.password.clone(), already)
        };

        // A moderation ban and an allowlist lock are checked before the
        // password logic - they exist for a different reason (who's
        // welcome at all, decided by the admin) than the brute-force
        // protection below (is this really the password's owner), and an
        // already-joined member is exempt from both: this only gates
        // joining, never membership already held.
        if !already_member {
            let rec = self.channels.get(name).expect("just looked up above");
            if rec.banned.contains(&joiner.name) {
                return Ok(vec![Outgoing {
                    to: id,
                    message: ServerMessage::ChannelJoinRejected {
                        name: name.to_string(),
                        kind: ChannelJoinRejection::UserBanned,
                    },
                }]);
            }
            if let Some(allowed) = &rec.join_lock
                && rec.admin.as_deref() != Some(joiner.name.as_str())
                && !allowed.contains(&joiner.name)
            {
                return Ok(vec![Outgoing {
                    to: id,
                    message: ServerMessage::ChannelJoinRejected {
                        name: name.to_string(),
                        kind: ChannelJoinRejection::NotOnAllowlist,
                    },
                }]);
            }
        }

        if !already_member && let Some(expected) = &channel_password {
            let attempt_key = (source_ip, name.to_string());
            let banned = self
                .channel_password_attempts
                .get(&attempt_key)
                .and_then(|rec| rec.banned_at)
                .is_some_and(|t| t.elapsed() < CHANNEL_PASSWORD_BAN_DURATION);
            if banned {
                return Ok(vec![Outgoing {
                    to: id,
                    message: ServerMessage::ChannelJoinRejected {
                        name: name.to_string(),
                        kind: ChannelJoinRejection::Banned,
                    },
                }]);
            }
            match password {
                None => {
                    return Ok(vec![Outgoing {
                        to: id,
                        message: ServerMessage::ChannelJoinRejected {
                            name: name.to_string(),
                            kind: ChannelJoinRejection::PasswordRequired,
                        },
                    }]);
                }
                Some(given) if !crypto::constant_time_eq(expected.as_bytes(), given.as_bytes()) => {
                    let rec = self
                        .channel_password_attempts
                        .entry(attempt_key)
                        .or_insert_with(|| PasswordAttemptRecord {
                            wrong_attempts: 0,
                            banned_at: None,
                        });
                    rec.wrong_attempts += 1;
                    let rejection = if rec.wrong_attempts > CHANNEL_MAX_PASSWORD_ATTEMPTS {
                        rec.banned_at = Some(Instant::now());
                        ChannelJoinRejection::Banned
                    } else {
                        ChannelJoinRejection::WrongPassword
                    };
                    return Ok(vec![Outgoing {
                        to: id,
                        message: ServerMessage::ChannelJoinRejected {
                            name: name.to_string(),
                            kind: rejection,
                        },
                    }]);
                }
                Some(_) => {
                    self.channel_password_attempts.remove(&attempt_key);
                }
            }
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
                outgoing.push(Outgoing {
                    to: id,
                    message: ServerMessage::UserJoined {
                        channel: name.to_string(),
                        user: info,
                    },
                });
            }
            outgoing.push(Outgoing {
                to: member_id,
                message: ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: joiner.clone(),
                },
            });
        }
        outgoing.push(Outgoing {
            to: id,
            message: ServerMessage::Joined {
                channel: ChannelInfo {
                    name: name.to_string(),
                    kind: channel_kind,
                },
                admin,
            },
        });

        // A brand-new *public* channel is announced to every other client -
        // the one-time ChannelList snapshot at connect otherwise never
        // updates, so this is the only way anyone learns it exists.
        // A private channel stays unadvertised; the joiner already has
        // `Joined` above.
        if !existed_before && channel_kind == ChannelKind::Public {
            for &other_id in all_client_ids {
                if other_id != id {
                    outgoing.push(Outgoing {
                        to: other_id,
                        message: ServerMessage::ChannelCreated {
                            channel: ChannelInfo {
                                name: name.to_string(),
                                kind: channel_kind,
                            },
                        },
                    });
                }
            }
        }

        Ok(outgoing)
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
            .map(|member_id| Outgoing {
                to: member_id,
                message: ServerMessage::UserLeft {
                    channel: name.to_string(),
                    user_id: id,
                },
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
            .map(|to| Outgoing {
                to,
                message: ServerMessage::UserOffline { user_id: id },
            })
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
            .map(|to| Outgoing {
                to,
                message: ServerMessage::ChannelRemoved {
                    name: name.to_string(),
                    reason: reason.clone(),
                },
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
    /// member at all.
    pub fn ban(
        &mut self,
        caller_name: &str,
        channel: &str,
        target_nickname: &str,
        target_id: Option<UserId>,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.require_caller_is_admin(channel, caller_name)?;
        rec.banned.insert(target_nickname.to_string());
        let mut out = Vec::new();
        if let Some(id) = target_id.filter(|id| rec.members.contains(id)) {
            let remaining = self.remove_member(id, channel);
            for to in remaining.into_iter().chain(std::iter::once(id)) {
                out.push(Outgoing {
                    to,
                    message: ServerMessage::UserBanned {
                        channel: channel.to_string(),
                        user_id: id,
                        nickname: target_nickname.to_string(),
                    },
                });
            }
        }
        Ok(out)
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
            .map(|&to| Outgoing {
                to,
                message: ServerMessage::UserUnbanned {
                    channel: channel.to_string(),
                    nickname: target_nickname.to_string(),
                },
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
            .map(|&to| Outgoing {
                to,
                message: ServerMessage::ChannelJoinLockUpdated {
                    channel: channel.to_string(),
                    by: caller_name.to_string(),
                },
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
            .map(|&to| Outgoing {
                to,
                message: ServerMessage::ChannelAdminChanged {
                    channel: channel.to_string(),
                    admin: Some(target_nickname.to_string()),
                },
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
    pub(crate) fn sweep_inactive(&mut self) {
        let Some(period) = self.deletion_unactivity_period else {
            return;
        };
        self.channels.retain(|name, rec| {
            name == DEFAULT_CHANNEL_NAME
                || !rec.members.is_empty()
                || rec.last_join_at.elapsed() < period
        });
    }
}
