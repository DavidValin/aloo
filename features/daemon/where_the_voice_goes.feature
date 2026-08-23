@US-038
Feature: Where a held shortcut sends your voice

  As someone talking from another app
  I want my voice to go somewhere I chose
  So that holding the shortcut is never a gamble

  --initial-focus is a *starting* position, not a standing instruction. It answers
  "where should a held shortcut go when this daemon comes up", and once
  that is answered the focus belongs to whoever is driving the session:
  someone who attaches, moves somewhere else and detaches again has said
  where they want to be.

  The events that would otherwise move it back are ordinary and frequent -
  a peer's connection dropping and returning, a channel being rejoined -
  and each would silently change where the next held shortcut goes, which
  is the one thing about this mode that must never be surprising.

  See docs/SPEC.md "Running in background mode".

  @AC-200
  Scenario: The focused person is focused the moment they appear
    Given a daemon focused on alice
    When alice appears
    Then the focus moves to them

  @AC-200
  Scenario: Somebody else appearing does not take the focus
    Given a daemon focused on alice
    When bob appears
    Then the focus is left where it was

  # The scenario this exists for: boot focused on alice, attach, move to
  # another channel, detach - then alice's connection drops and returns.
  @AC-200
  Scenario: A focused person reconnecting does not drag the focus back
    Given a daemon focused on alice
    And the focus has already been placed
    When alice appears
    Then the focus is left where it was
    And it is still an event worth announcing

  @AC-200
  Scenario: A focused channel being rejoined does not pull the focus back
    Given a daemon focused on the channel "ops"
    And the focus has already been placed
    When the focus is placed
    Then the focus is left where it was

  # The latch lives in the running plan and is never written to disk, so a
  # fresh start honours --initial-focus again.
  @AC-200
  Scenario: Restarting with --initial-focus puts the focus back
    Given a daemon focused on alice
    And the focus has already been placed
    When the daemon is stopped and started again with the same --initial-focus
    And alice appears
    Then the focus moves to them
