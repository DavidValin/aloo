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

  @AC-047
  Scenario: A nickname seen for the first time is simply remembered
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    Then it is a first sighting

  @AC-047
  Scenario: The same nickname with the same key passes without comment
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    And alice is seen with the key "key-a"
    Then it matches what was pinned

  @AC-048 @TB-086
  Scenario: A nickname returning under a different key is flagged, then re-pinned anyway
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    And alice is seen with the key "key-b"
    Then it is flagged as a mismatch against the previous key "key-a"
    And alice is now pinned to the new key

  @AC-049 @AC-064
  Scenario: Nothing is shown when nothing is wrong
    Given I am connected and viewing a channel
    Then no review popup is shown

  @AC-064
  Scenario: A mismatch opens a review popup naming the peer, with Accept and Reject on offer
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    Then a review popup names bob with Accept and Reject buttons

  @AC-065
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

  @AC-065
  Scenario: Rejecting a mismatched key is never persisted and keeps messages held
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And bob sends the channel message "trust me" while unresolved
    And I reject the review
    Then no review popup is shown
    And the message "trust me" is not shown yet
    And bob is still flagged as unverified

  @AC-066
  Scenario: Selecting an unverified peer reopens the review instead of a private room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And I reject the review
    And I move focus to the sidebar
    And I press Enter
    Then a review popup names bob with Accept and Reject buttons
    And no private room is open

  @AC-049 @AC-067
  Scenario: A second mismatch waits its turn behind the one already showing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob's identity mismatches
    And carol's identity mismatches
    Then a review popup names bob with Accept and Reject buttons
    When I reject the review
    Then a review popup names carol with Accept and Reject buttons

  @AC-068
  Scenario: A channel message still reaches everyone else while one member is unverified
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob's identity mismatches
    And I reject the review
    And I type "hello everyone" into the compose bar
    And I press Enter
    Then the outgoing channel message excludes bob but includes carol

  @AC-050 @TB-096 @TB-098
  Scenario: A reconnecting rsa_per_msg peer who can prove continuity is recognised silently
    Given bob's continuity key is pinned from a previous session
    When bob reconnects and re-asserts that same key, signed by itself
    Then he is recognised as the same person, with no warning
    And an ordinary in-session rotation is still preferred over the pinned key

  @AC-050 @TB-097
  Scenario: A reconnect nobody can vouch for is not quietly trusted
    Given bob's continuity key is pinned from a previous session
    When bob reconnects and presents a key nobody can vouch for
    Then nothing vouches for him and the reconnect is not trusted

  @AC-069
  Scenario: A familiar nickname reconnecting via rsa_per_msg is gated on sight, before it even tries to prove continuity
    Given I am connected and viewing a channel
    And bob's nickname is already linked to a key from a previous session
    When bob rejoins using rsa_per_msg without proving continuity
    Then a review popup names bob with Accept and Reject buttons
