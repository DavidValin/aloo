@US-011
Feature: Recognising a peer across reconnects

  As a user talking to the same people over time
  I want to be told when a familiar nickname comes back under a key it cannot
  prove is still theirs
  So that I can judge whether it is really them

  Nicknames are freed the instant their holder disconnects, and every peer's
  key is trusted on first sight - so nothing in the protocol itself tells
  "alice reconnecting" apart from "someone else who took the name". This is
  the local record that closes that gap, the way known_hosts does. A mismatch
  opens a blocking Accept/Reject review rather than silently auto-trusting
  the new key - messaging with that peer stays gated until it's decided, but
  a decision is never permanent: a rejected peer stays reachable for
  reconsideration, never silently locked out for good. See docs/PROTOCOL.md
  section 12.

  @AC-047 @pqhybrid @with_server @without_reachable_server
  Scenario: A nickname seen for the first time is simply remembered
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    Then it is a first sighting

  @AC-047 @pqhybrid @with_server @without_reachable_server
  Scenario: The same nickname with the same key passes without comment
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    And alice is seen with the key "key-a"
    Then it matches what was pinned

  @AC-048 @TB-086 @pqhybrid @with_server @without_reachable_server
  Scenario: A nickname returning under a different key is flagged, then re-pinned anyway
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    And alice is seen with the key "key-b"
    Then it is flagged as a mismatch against the previous key "key-a"
    And alice is now pinned to the new key

  @AC-047 @TB-087 @pqhybrid @with_server @without_reachable_server
  Scenario: A second device is pinned independently, without disturbing the first
    Given a local identity store with nothing pinned yet
    When alice is seen on device "laptop" with the key "key-laptop"
    And alice is seen on device "phone" with the key "key-phone"
    Then alice on device "laptop" is pinned to the key "key-laptop"
    And alice on device "phone" is pinned to the key "key-phone"

  @AC-048 @TB-086 @pqhybrid @with_server @without_reachable_server
  Scenario: Accepting one device's new key never disturbs another device's pin
    Given a local identity store with nothing pinned yet
    When alice is seen on device "laptop" with the key "key-laptop"
    And alice is seen on device "phone" with the key "key-phone"
    And alice's device "phone" is re-pinned to the key "key-phone-2"
    Then alice on device "phone" is pinned to the key "key-phone-2"
    And alice on device "laptop" is still pinned to the key "key-laptop"

  @AC-049 @AC-064 @pqhybrid
  Scenario: Nothing is shown when nothing is wrong
    Given I am connected and viewing a channel
    Then no review popup is shown

  @AC-064 @pqhybrid
  Scenario: A mismatch opens a review popup naming the peer, with Accept and Reject on offer
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    Then a review popup names bob with Accept and Reject buttons

  @AC-065 @pqhybrid
  Scenario: Accepting a mismatched key trusts it and reveals what arrived while it was pending
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And bob sends the channel message "hi, it's still me" while unresolved
    Then the message "hi, it's still me" is not shown yet
    When I accept the review
    Then no review popup is shown
    And the message "hi, it's still me" now appears in the channel
    And bob is no longer flagged

  @AC-065 @pqhybrid
  Scenario: Rejecting a mismatched key is never persisted and keeps messages held
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And bob sends the channel message "trust me" while unresolved
    And I reject the review
    Then no review popup is shown
    And the message "trust me" is not shown yet
    And bob is still flagged as unverified

  @AC-066 @pqhybrid
  Scenario: Selecting an unverified peer reopens the review instead of a private room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And I reject the review
    And I move focus to the sidebar
    And I press Enter
    Then a review popup names bob with Accept and Reject buttons
    And no private room is open

  @AC-049 @AC-067 @pqhybrid
  Scenario: A second mismatch waits its turn behind the one already showing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob's identity mismatches
    And carol's identity mismatches
    Then a review popup names bob with Accept and Reject buttons
    When I reject the review
    Then a review popup names carol with Accept and Reject buttons

  @AC-068 @pqhybrid
  Scenario: A channel message still reaches everyone else while one member is unverified
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob's identity mismatches
    And I reject the review
    And I type "hello everyone" into the compose bar
    And I press Enter
    Then the outgoing channel message excludes bob but includes carol

  @AC-166 @pqhybrid
  Scenario: A mismatch gates messaging immediately but withholds the review until the new connection is known
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches but the new connection is not yet known
    Then bob is still flagged as unverified
    And no review popup is shown
    When bob's new connection becomes known
    Then a review popup names bob with Accept and Reject buttons

