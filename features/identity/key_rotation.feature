@US-010
Feature: Rotating a key for every message

  As a user who picked rsa_per_msg
  I want a fresh keypair per peer, replaced on every message and signed by the
  key it replaces
  So that a key which protected an old message no longer exists to be stolen

  Every rotation is signed with the key it supersedes, and the recipient is
  bound into the signed bytes so a rotation cannot be replayed at somebody
  else. See docs/PROTOCOL.md sections 11.3 and 11.4.

  @AC-044 @TB-070
  Scenario: A properly signed rotation is trusted
    Given bob holds a key I currently trust
    When bob rotates to a fresh key, signed with the one it replaces
    Then the rotation is accepted and the new key becomes usable

  @AC-044 @TB-070
  Scenario: A forged rotation changes nothing
    Given bob holds a key I currently trust
    When someone forges a rotation with a key of their own
    Then the rotation is refused and the old key stays trusted

  @AC-044
  Scenario: A rotation tampered with in flight is refused
    Given bob holds a key I currently trust
    When bob rotates to a fresh key, signed with the one it replaces
    And the rotated key bytes are tampered with in flight
    Then the rotation is refused and the old key stays trusted

  @AC-044 @TB-069
  Scenario: A rotation meant for me cannot be replayed at someone else
    Given bob holds a key I currently trust
    When bob rotates to a fresh key, signed with the one it replaces
    Then that same rotation does not verify when replayed at someone else

  @AC-045 @TB-080
  Scenario: Messages typed before a peer's next key arrives are held, then sent in order
    Given bob uses rsa_per_msg and I have already used his current key
    When I type "first" and then "second" to him
    Then both messages are held, not sent
    When bob's next key arrives
    Then they go out together, "first" before "second"
    And his key is stale again until the next rotation

  @AC-046 @TB-085
  Scenario: A key being regenerated shows a spinner, and stops showing one when it is done
    Given I am connected and viewing a channel
    Then no spinner is shown
    When a key regeneration starts
    Then a spinner appears right after the help hint
    When the regeneration keeps running for another moment
    Then the spinner has moved on to its next frame
    When every regeneration finishes
    Then no spinner is shown
    And a restarted spinner begins from the first frame again
