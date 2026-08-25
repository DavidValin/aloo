@US-039
Feature: A punched peer becomes someone I can actually see and talk to

  As someone running aloo in the background with direct punching on
  I want a peer reached with no server to appear and behave like any other
  So that my channels, my focus and my push-to-talk work the same either way

  A punch on its own only opens a path. What turns that path into a person
  is something that authenticates them: an envelope that opens under the
  key already pinned for their nickname - which also carries the channels
  they are in, so both sides can place each other in the channels they
  share - or, for a pair who hold a one-time pad and no keybundles, the pad
  opening a message they sent. Until one of those arrives nobody is
  registered: the nickname on a punch datagram is unauthenticated and names
  nobody. See docs/PROTOCOL.md 7.1.5.

  @AC-215 @direct_otp @without_reachable_server
  Scenario: An unauthenticated punch does not make anyone a peer
    Given alice has no pinned identity for "mallory"
    Then "mallory" cannot become an addressable peer

  @AC-215 @AC-259 @direct_otp @without_reachable_server
  Scenario: A pin that is not a keybundle still names someone, for the pad to prove
    Given alice has a pinned identity for "bob" that is not a pq_hybrid one
    Then "bob" is named by that pin, but nothing is sealed to it
    And only a pad can prove "bob" is who the pin says

  # No-server reference table row 3: the sender's device_id rides in the
  # clear alongside every pad-wrapped message, checked before the pad is
  # ever touched (docs/PROTOCOL.md 16.2, device-pinning plan §5). A copied
  # pad file used from a second machine is refused, not merged - the exact
  # same ciphertext still decrypts cleanly once the genuinely bound device
  # sends it.
  @AC-317 @direct_otp @without_reachable_server
  Scenario: A copied pad claimed from a different device is held, not delivered
    Given alice and bob reach each other directly and hold a pad for each other
    When alice sends bob "first"
    Then bob reads it, and registers alice because the pad opened it
    And bob's acknowledgement proves he decrypted it
    When alice sends bob "hello from a copied pad" but claims to be device "alices-phone-not-her-laptop"
    Then bob holds it unread, and the pad stays bound to alice's real device
    Then bob reads it once alice's real device claims the same message

  @AC-214
  Scenario: A punched peer joins the channels we both are in
    Given alice has joined "general" and "dev"
    When bob announces over the direct link that he is in "general" and "elsewhere"
    Then bob is placed in "general"
    And bob is not placed in "elsewhere"

  @AC-214
  Scenario: The announcement is authoritative, so leaving is announced by omission
    Given alice has joined "general" and "dev"
    And bob is already placed in "general"
    When bob announces over the direct link that he is in "dev"
    Then bob is placed in "dev"
    And bob is removed from "general"

  @AC-214
  Scenario: A peer who leaves every shared channel is still someone I can DM
    Given alice has joined "general" and "dev"
    And bob is already placed in "general"
    When bob announces over the direct link that he is in no channels
    Then bob is removed from "general"
    And bob is still an addressable peer

  @TB-224
  Scenario: Leaving a channel does not tear down a link the schedule owns
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    Then leaving a channel does not forget the link to bob

  @TB-214
  Scenario: Listing someone who has not listed you reaches nobody
    Given bob lists peter for direct punching
    And peter lists somebody else instead
    When both of them punch on the shared grid
    Then bob has no link to peter
    And peter has no link to bob
    And peter has no record of bob at all

  # Reconciling an unpinned nickname against an already-pinned key
  # (docs/PROTOCOL.md 7.1.5's continuation): a `direct_punch_to` name that
  # punches successfully but has no key pinned at all asks before doing
  # anything, rather than staying a silent transport-only link forever.
  # The popup mechanics are proven here against `UiState` directly, the
  # same way the identity review popup's own scenarios are; the real
  # cryptographic scan that finds a match is proven end to end with two
  # real punched sessions in test/daemon_session_test.rs, since it needs a
  # live link and a live pad/keybundle to mean anything.

  @AC-275 @pqhybrid
  Scenario: A configured but unpinned nickname's pq_hybrid proof asks first
    Given I am connected and viewing a channel
    And carol is a direct-punch target alice has no key pinned for
    When carol's punched link sends a pq_hybrid ChannelPresence proof
    Then alice is asked whether to check her local keys for carol

  @AC-275 @pqhybrid_otp
  Scenario: A configured but unpinned nickname's pad-wrapped proof asks first
    Given I am connected and viewing a channel
    And carol is a direct-punch target alice has no key pinned for
    When carol's punched link sends a pad-wrapped message proof
    Then alice is asked whether to check her local keys for carol

  @AC-276 @AC-277
  Scenario: Confirming a found match asks to use it, then reports it chosen
    Given I am connected and viewing a channel
    And carol is a direct-punch target alice has no key pinned for
    And carol's punched link sends a pq_hybrid ChannelPresence proof
    And alice agrees to check her local keys
    When the check finds that dave's key matches carol's request
    Then alice is asked whether to use dave's key for carol
    When alice confirms using dave's key
    Then confirming carol's match is what alice's answer asked for

  @AC-279
  Scenario: Declining the first question leaves no review outstanding
    Given I am connected and viewing a channel
    And carol is a direct-punch target alice has no key pinned for
    And carol's punched link sends a pq_hybrid ChannelPresence proof
    When alice declines to check her local keys
    Then no unknown-peer review is left open for carol

  @AC-279
  Scenario: Declining the offered match discards only that offer
    Given I am connected and viewing a channel
    And carol is a direct-punch target alice has no key pinned for
    And carol's punched link sends a pq_hybrid ChannelPresence proof
    And alice agrees to check her local keys
    And the check finds that dave's key matches carol's request
    When alice declines the offered match
    Then declining carol's match is what alice's answer asked for
    And no unknown-peer review is left open for carol
