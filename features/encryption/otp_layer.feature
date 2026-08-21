@US-033
Feature: Layering one-time-pad encryption over an established pq_hybrid conversation

  As a user who wants an extra, independent layer of secrecy on top of
  pq_hybrid for a specific contact
  I want the real otp command (github.com/DavidValin/otp-toolkit) to wrap and
  unwrap my pq_hybrid sends to that contact, provisioned only when I
  explicitly ask
  So that even a future break of pq_hybrid alone does not expose that
  conversation, and I never send a message before the previous one was
  genuinely acknowledged

  Every cryptographic operation here shells out to the real `otp` command -
  aloo contains no one-time-pad cryptography or keychain-format code of its
  own. See docs/PROTOCOL.md section 16.

  @AC-136
  Scenario: Both sides converge on the same otp contact name for each other
    Given alice and bob each have a pq_hybrid identity
    Then alice and bob compute the very same otp contact name for each other

  @AC-136
  Scenario: A message wrapped under the pad cannot be read until it is unwrapped
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice seals "meet me at six" for bob and wraps it under the pad
    Then the wrapped bytes do not open as a pq_hybrid send directly
    And bob unwraps it and reads back exactly what was sent

  @AC-137
  Scenario: A second message under the pad waits for a genuine delivery acknowledgement
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice sends "first" to bob under the pad
    Then "first" was sent immediately
    When alice sends "second" to bob under the pad
    Then "second" is held back, not sent
    When bob's delivery ack for "first" arrives
    Then the held message "second" is sent

  @AC-138
  Scenario: A keychain contact provisioned outside the app is adopted, not regenerated
    Given alice has an otp contact for bob provisioned out of band
    When alice checks whether that contact can be adopted
    Then it is adopted without generating a fresh pad

  @AC-139
  Scenario: A generate-confirm prompt must be answered before anything is generated or sent
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I am asked to generate a fresh otp pad for bob
    Then a prompt asks whether to generate and share a fresh pad with bob
    When I press Enter
    And I type "50"
    And I press Enter
    Then generating the pad was confirmed with a 50MB size

  @AC-139
  Scenario: Declining the generate prompt cancels locally without sending anything
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I am asked to generate a fresh otp pad for bob
    And I press Right
    And I press Enter
    Then generating the pad was cancelled

  @AC-139
  Scenario: An incoming invite names the sender and must be explicitly accepted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob invites me to start an otp session
    Then an invite popup names bob
    When I press Enter
    Then the otp invite was accepted

  @AC-139
  Scenario: Rejecting an incoming invite is also an explicit choice
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob invites me to start an otp session
    And I press Tab
    And I press Enter
    Then the otp invite was rejected

  @AC-139
  Scenario: A second invite from a different sender waits its turn behind the first
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob invites me to start an otp session
    And carol invites me to start an otp session
    Then an invite popup names bob
    When bob's invite is answered
    Then an invite popup names carol

  @AC-139
  Scenario: The status notice announces whether a session started or was cancelled
    Given I am connected and viewing a channel
    Then no otp status notice is shown
    When an otp session started notice arrives
    Then an otp status notice says "OTP session started"
    When an otp session cancelled notice arrives
    Then an otp status notice says "OTP session cancelled"

  @AC-140
  Scenario: An unrecognized slash command in a private room is never sent as text
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "/otpp" into the compose bar
    And I press Enter
    Then nothing happens
    And an otp status notice says "unknown command: /otpp"

  @TB-186
  Scenario: A pad far larger than one network datagram still arrives whole
    Given alice generates a fresh 2MB pad for bob
    When it is sent to bob in many small pieces
    Then bob's reassembled pad is byte-identical to the one alice generated

  @AC-142
  Scenario: An invitation that is never accepted leaves nothing behind
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob never accepts
    Then alice holds no otp contact for bob
    And a later invitation from alice to bob still succeeds

  @AC-142
  Scenario: A refused invitation does not block the next one
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob refuses
    Then alice holds no otp contact for bob
    And a later invitation from alice to bob still succeeds

  @AC-142
  Scenario: A refused invitation does not block one going the other way
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob refuses
    Then a later invitation from bob to alice still succeeds

  @AC-142
  Scenario: A pad owed to a peer is re-offered unchanged rather than regenerated
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob never accepts
    Then the pad alice would re-send is byte-identical to the one she generated

  @AC-142
  Scenario: Both users invite each other at once and only one pad survives
    Given alice and bob each have a pq_hybrid identity
    When alice and bob both generate a pad for each other before either answers
    Then both sides agree on which pad survives
    And the conceding side keeps no pad of its own

  @AC-243
  Scenario: A message details popup names the pad position it spent
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And the otp session with bob is active
    And bob's pad has sent 4 messages over 480 bytes and received 9 over 900
    And focus is on the compose
    When I type "under the pad"
    And I press Enter
    And I open the details of my last message
    Then the details name pad sequence 5 at offset 480
    And the details name the key file ending "_enc.key"

  @AC-243
  Scenario: An arriving message names the receiving pad instead
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And the otp session with bob is active
    And bob's pad has sent 4 messages over 480 bytes and received 9 over 900
    When bob has sent me the private message "psst"
    And I open the details of my last message
    Then the details name pad sequence 10 at offset 900
    And the details name the key file ending "_dec.key"

  @AC-246
  Scenario: A pad session marks that person wherever they are named
    Given I am connected and viewing a channel
    And bob is in the channel with me using pq_hybrid
    And carol is in the channel with me using pq_hybrid
    And I have opened a private room with bob
    And the otp session with bob is active
    Then bob carries the OTP tag on the DM selector
    When I press the [ key
    Then bob carries the OTP tag in the user list instead of their own
    And carol still carries their own tag
