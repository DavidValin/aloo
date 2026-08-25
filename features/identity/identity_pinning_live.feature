@US-011
Feature: Identity pinning over a real connection

  As a user reconnecting, or being reconnected to, over a genuine network
  link
  I want the identity check to actually run - not merely be simulated -
  and its result to actually reach disk
  So that the popups and pins the rest of this feature describes are
  backed by something real, not only by `UiState` standing in for it

  Every other scenario in this area drives `UiState`/`IdStore` directly,
  standing in for what `session.rs`'s live wiring - `check_identity`,
  `finalize_identity_pin`, the `AcceptIdentity` handler - would do, since
  that wiring itself needs a real socket to reach at all. These scenarios
  are the exception: two real `run_daemon_session`s, against a real
  server, over real loopback sockets, driving that wiring for real and
  reading what actually landed on disk afterward. See docs/PROTOCOL.md
  section 12 and docs/TESTING.md's "device id/last-seen-address
  orchestration" and "AcceptIdentity's network-facing side effects" rows.

  @AC-165 @pqhybrid @with_server
  Scenario: A live connection's address is actually recorded on disk
    Given a server that anyone may connect to
    And alice joins the server for real, into "general"
    When bob joins the server for real, into "general"
    Then alice's screen shows "bob" within 10 seconds
    And alice's on-disk identity store records bob's last-seen address

  @AC-048 @pqhybrid @with_server
  Scenario: A live reconnect under a different key is reviewed, and Accept actually persists it
    Given a server that anyone may connect to
    And alice already has bob pinned under device "old-machine" to a different key
    And alice joins the server for real, into "general", with that pin in place
    When bob joins the server for real, into "general"
    Then alice's screen shows an identity review naming bob within 15 seconds
    When alice accepts the pending identity review
    Then alice's on-disk identity store pins bob to bob's newly connected key, under a new device
