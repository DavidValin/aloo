@US-013
Feature: When someone's connection closes

  As a user who has been talking to someone
  I want their history to stay reachable once they disconnect, without
  pretending they are still around
  So that I can read back what we said

  What happens depends on whether there is anything to keep them around for:
  a conversation, or nothing. The server has no visibility into that, so the
  decision is entirely the client's. See docs/SPEC.md Functionality #8.

  @AC-052
  Scenario: Someone I have talked to stays listed, greyed out
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And bob has sent me the private message "hi"
    And I have a direct connection to carol
    When bob goes offline
    Then bob is still listed in the channel
    And bob is rendered in gray while carol stays green

  @AC-052
  Scenario: Someone I have never talked to is simply removed
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob goes offline
    Then bob is dropped from the channel list

  @AC-052 @TB-104
  Scenario: Opening an empty room is not the same as having talked
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When bob goes offline
    Then bob is dropped from the channel list

  # What may actually be submitted here depends on queue_send_messages
  # (US-064): an ordinary message is held for them while it is on, and
  # refused while it is off. Both are in
  # features/messaging/queued_sends.feature; what this one pins is the
  # room itself - the red notice, and that typing is never blocked.
  @AC-053
  Scenario: An offline peer's room shows a red notice but can still be typed into
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    And bob has gone offline
    When I open a private room with bob
    Then focus moves to the compose bar
    And the compose bar shows an offline notice in red
    When I type "are you there"
    Then the compose bar holds "are you there"
    When I press Enter
    Then nothing is sent
    And the private room holds only 2 messages
    And the compose bar holds "are you there"

  @AC-053 @TB-105
  Scenario: Another person's room still works normally
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And bob has sent me the private message "hi"
    And bob has gone offline
    When I open a private room with carol
    And I type "hey carol"
    And I press Enter
    Then sending the private message "hey carol" to carol is requested

  # Only when there is nowhere to hold the recording. With
  # `queue_send_messages` on it is held for them like anything else, which
  # is what that switch is for - see features/messaging/queued_sends.feature.
  @AC-054 @AC-426
  Scenario: Holding Space at an offline peer does nothing when there is no queue
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    And bob has gone offline
    And I have opened a private room with bob
    And focus is on the log
    When I hold Space
    Then no recording starts

  @AC-426
  Scenario: Holding Space at an offline peer records for them when there is
    Given queueing sends is on
    And I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    And bob has gone offline
    And I have opened a private room with bob
    And focus is on the log
    When I hold Space
    Then a recording starts

  @AC-055 @TB-020
  Scenario: Going offline is permanent for the session
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob goes offline
    Then bob stays offline even if a join for them arrives again

  # A UserId is per-connection and never reused, so someone reconnecting
  # arrives as a stranger by id. The nickname is what carries them across.
  @AC-248
  Scenario: Someone who comes back continues where they left off
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "before"
    And bob has gone offline
    When bob reconnects under a new id
    Then bob is listed once in the channel
    And the private room with bob still holds "before"
    And bob is no longer offline
