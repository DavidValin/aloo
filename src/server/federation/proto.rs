//! The server-to-server wire protocol (docs/PROTOCOL.md's federation
//! section). A separate enum from `crate::proto`'s `ClientMessage`/
//! `ServerMessage` on purpose: those are client-facing, and a federation
//! link is a different trust domain (mutually PQ-hybrid-authenticated
//! between two servers, `crate::server::federation::handshake` - no TLS,
//! no certificates) carrying different concerns (identity/routing
//! metadata, never message content).
//!
//! Framed exactly like the client protocol - `crate::control::{ControlReader,
//! ControlWriter}` is generic over any `Serialize`/`Deserialize` type, so
//! it is reused here purely for its length-prefixed bincode framing, and
//! for the AES-256-GCM sealing the handshake enables once its key exchange
//! completes (`ControlReader::enable`/`ControlWriter::enable`) - the same
//! "starts clear, then switches over" shape the client control channel
//! uses, just with a mutually-authenticated key exchange ahead of it
//! instead of an unauthenticated one.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::PqEncapKeys;
use crate::proto::{ChannelJoinRejection, ChannelKind, KeyMode};
use crate::server::mail::StoredMail;

/// One channel's federation-visible metadata - deliberately not
/// `crate::proto::ChannelInfo`, which has no `owner` field, and
/// deliberately excludes everything else `ChannelRecord` holds
/// (members, password, admin, bans, join-lock): a peer needs to know a
/// channel exists, its kind, and who owns it, never who is in it or what
/// unlocks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedChannelInfo {
    pub name: String,
    pub kind: ChannelKind,
    /// The `server_federation_id` of whichever server this channel was
    /// created on - the only server that ever holds its password.
    pub owner: String,
}

/// Enough of a federated member's identity to show them in a channel's
/// member list on a server they have no live connection to: which server
/// they actually are connected to, their nickname there, and the public
/// bundle peers would seal to if federated peer-to-peer linking existed
/// (it does not yet - see docs/PROTOCOL.md §18.5 - so this is carried
/// forward for when it does, and meanwhile just lets a receiving server
/// build a `UserInfo` good enough to display). Never carries a password
/// or anything membership-unrelated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteIdentity {
    pub server: String,
    pub nickname: String,
    pub public_key_der: Vec<u8>,
    pub key_mode: KeyMode,
}

/// Server-to-server messages. The first two variants, `Hello` and
/// `KeyExchange`, are the handshake itself
/// (`crate::server::federation::handshake`) and travel unsealed - every
/// later message flows only after both sides have signed and verified
/// each other's `Hello`/`KeyExchange` and switched the link to encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederationMessage {
    /// The first message either side sends immediately on connecting: a
    /// liveness/identity announcement plus this side's fresh, per-connection
    /// ML-KEM-1024+X25519 encryption keys and a random nonce. Not itself a
    /// trust decision - `self_id` is only believed once `KeyExchange`
    /// proves, via a signature from the durable identity pinned for that
    /// id, that whoever sent this `Hello` really holds it.
    Hello {
        self_id: String,
        advertise_addr: String,
        /// Where an ordinary *client* should connect for this server
        /// (`server_federation_client_addr`), so a peer can name it to a
        /// user who logged in on the wrong server (§18.4). `None` if its
        /// operator never configured one. Every other address on a
        /// federation link is the server-to-server port, which no client
        /// ever speaks to - which is exactly the bug this closes.
        client_addr: Option<String>,
        ephemeral_encap: PqEncapKeys,
        nonce: [u8; 32],
    },
    /// The handshake's second and last message: this side's contribution
    /// to the shared session key (wrapped for the peer's `Hello.ephemeral_encap`,
    /// the same `crypto::pq::wrap_key_for` construction a message send
    /// uses), plus a durable-identity signature over both sides' `Hello`s -
    /// what makes `self_id` trustworthy and binds the key exchange to this
    /// exact session, so neither can be substituted or replayed from an
    /// earlier one. See `handshake::handshake` for the exact transcript and
    /// key derivation.
    KeyExchange {
        kem_ciphertext: Vec<u8>,
        wrapped_key: [u8; 32],
        eph_x25519_pub: [u8; 32],
        /// `(mldsa_sig, rsa_sig)` - `crypto::pq::sign_with_identity`'s
        /// output over the handshake transcript.
        sig: (Vec<u8>, Vec<u8>),
    },
    /// Liveness, nothing more: sent on a link that has been idle, and
    /// acted on purely by arriving. A link that hears nothing at all for
    /// long enough is torn down and redialed, which is the only way to
    /// notice a socket that TCP will never report as broken - a vanished
    /// host, a NAT that dropped its state, a rebooted router.
    Ping,
    /// Sent once, right after the handshake, by whichever side just connected:
    /// every nickname/channel this server's directory currently knows
    /// about (its own registrations and whatever it already learned from
    /// other peers), so a newly linked peer's directory starts complete
    /// rather than growing one gossip message at a time.
    DirectorySnapshot {
        nicknames: Vec<(String, String)>,
        channels: Vec<FederatedChannelInfo>,
    },
    /// Gossip: `nickname` was just registered on `owner`. Sent to every
    /// linked peer the moment a local registration succeeds, so the rest
    /// of the federation's directories stay current without waiting for
    /// the next full snapshot.
    NicknameRegistered { nickname: String, owner: String },
    /// Gossip: `channel` was just created on its `owner`. For a *public*
    /// channel, every receiving server also mirrors it into its own local
    /// channel registry right away (empty of members) and tells its own
    /// connected clients about it (`ServerMessage::ChannelCreated`) - the
    /// whole federation is meant to see one shared public channel list,
    /// not just whichever servers a client happens to have joined
    /// something on already. A private channel is never mirrored this
    /// way; it stays reachable only by knowing its name, exactly like a
    /// local one.
    ChannelRegistered { channel: FederatedChannelInfo },
    /// Gossip: a channel owned by `owner` was removed (`/delete-channel`,
    /// a superadmin's removal, or the inactivity sweep) - clears `owner`'s
    /// claim on `name` from every peer's directory (see
    /// `directory::FederationDirectory::remove_channel` for what that
    /// means when the name was `Conflicted`).
    ChannelRemoved { name: String, owner: String },
    /// Gossip: `nickname`, registered on `owner`, was removed (a
    /// superadmin's `/remove-account`) - clears `owner`'s claim on it the
    /// same way `ChannelRemoved` does for a channel.
    NicknameRemoved { nickname: String, owner: String },

    /// Sent by a server whose local client wants to join `channel`, to
    /// the server the federation directory says owns it - the only server
    /// that ever checks `password`, since it is the only one that ever
    /// holds it. `request_id` is unique per requester (not global), and
    /// only ever echoed back on the same link it went out on.
    /// `joiner_public_key_der`/`joiner_key_mode` carry the requester's own
    /// identity forward so the home server can name it in the
    /// `ChannelMemberJoined` gossip it sends on to every other linked
    /// peer - the home server has no other way to learn it, since this
    /// joiner has no connection to it at all.
    JoinProxyRequest {
        request_id: u64,
        channel: String,
        joiner_nickname: String,
        password: Option<String>,
        joiner_public_key_der: Vec<u8>,
        joiner_key_mode: KeyMode,
    },
    /// The home server's answer to one `JoinProxyRequest`.
    JoinProxyResponse { request_id: u64, outcome: JoinProxyOutcome },
    /// Best-effort: a local client of the sender left (or disconnected
    /// from) `channel`, owned by the recipient - nothing waits on this,
    /// so there is no response.
    LeaveProxyNotice { channel: String, nickname: String },

    /// Gossiped by a channel's *home* server every time anyone - a local
    /// client of its own, or a federation peer's, via `JoinProxyRequest` -
    /// joins one of its channels, to every currently-linked peer (whether
    /// or not that peer has any members in this channel itself - a peer
    /// with none simply merges and does nothing with it). Only the home
    /// server ever sends this: it is the only server with full visibility
    /// of a channel's real membership. A receiving server that already
    /// mirrors `channel` (as its own home, or because one of its own
    /// clients joined it via proxy) records `member` and tells its local
    /// members about the new arrival; one that doesn't mirror it at all
    /// has nothing to update and drops this silently.
    ChannelMemberJoined { channel: String, member: RemoteIdentity },
    /// The departure mirror of `ChannelMemberJoined` - `server`/`nickname`
    /// identify the leaving member the same way `RemoteIdentity` does,
    /// without needing to repeat their key material.
    ChannelMemberLeft { channel: String, server: String, nickname: String },
    /// Who is in `channel` *right now*, in full, sent by its home server
    /// to a peer whose link has just come up - one message per channel it
    /// owns that has anyone in it. `ChannelMemberJoined`/`ChannelMemberLeft`
    /// are live-only: gossip sent while a link was down is never re-sent,
    /// so without this a peer that linked late (or relinked after a drop,
    /// having forgotten that peer's members - see
    /// `ChannelsRegistry::forget_members_of_server`) would show a busy
    /// channel as empty, forever. The list is authoritative and *replaces*
    /// what the receiver had for that channel, rather than merging into
    /// it, which is what lets it correct a stale member as well as a
    /// missing one.
    ChannelMembership { channel: String, members: Vec<RemoteIdentity> },

    /// Hands an uploaded OTP mail's opaque ciphertext (plus its routing
    /// metadata) to the federated server that owns `mail.to` - the
    /// uploading server keeps its own durable copy until this is
    /// acknowledged (`MailForwardAck`), so a peer link that is briefly
    /// down never loses mail, only delays it.
    MailForward { mail: StoredMail },
    /// Confirms a `MailForward` was durably stored - what lets the
    /// originating server forget its own now-redundant copy.
    MailForwardAck { mail_id: String },
    /// Relays a delivery receipt back to the server that owns `from`, so
    /// its own `OtpMailFetch`/live-notify path can tell that sender their
    /// mail was delivered, exactly as it would if the sender and
    /// recipient shared one server.
    MailDeliveredReceipt { mail_id: String, from: String, to: String },
    /// Confirms a `MailDeliveredReceipt` was recorded, so the relaying
    /// server can drop its own copy - the mirror of `MailForwardAck`, and
    /// needed for the same reason. A receipt for a *cross-server* sender
    /// can never be cleared the ordinary way (`MailStore::forget_receipt`
    /// requires the sender themselves to claim it, and they authenticate
    /// on a different server entirely), so without this every relayed
    /// receipt lives forever on the recipient's server and is re-sent in
    /// full on every single reconnect - growing with all-time cross-server
    /// mail volume, and paid again on every link flap.
    MailReceiptAck { mail_id: String },
}

/// The home server's answer to a `JoinProxyRequest` - the same five
/// reasons `crate::proto::ChannelJoinRejection` already gives a local
/// joiner, plus the two outcomes unique to a cross-server request: a
/// clean grant (with the channel's real kind/admin, since the requester
/// has never seen this channel before), and a stale directory naming a
/// channel this server does not actually have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinProxyOutcome {
    Joined { kind: ChannelKind, admin: Option<String> },
    Rejected(ChannelJoinRejection),
    UnknownChannel,
}
