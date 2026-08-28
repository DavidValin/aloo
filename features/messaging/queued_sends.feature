@US-064
Feature: Saying something to someone who is not there

  As a user talking to one person who is offline as often as not
  I want what I send them held until they are reachable
  So that a walkie-talkie to one other person works without both of us being online at once

  Everything here is what `queue_send_messages` turns on. With it off,
  nothing is held at all: a send goes straight at the transport, which
  keeps its own short in-memory queue for a link that is merely being
  punched and reports the content lost once that minute is up. See
  docs/SPEC.md Functionality #34; the Ctrl+S switch itself is
  features/settings/settings_popup.feature.

  What is held is exactly what would have gone on the wire, still sealed,
  so a held message keeps the layering it was sent under. Nothing ever
  ages out of the queue or is evicted to make room for something newer -
  the one thing that removes a held message is the contact it was sealed
  for no longer being on this machine.

  # ------------------------------------------------------------------
  # What is held, and what is not
  # ------------------------------------------------------------------

  @AC-408
  Scenario: Text and voice are held, files are not
    Given queueing sends is on
    Then a text message is held for someone unreachable
    And a pad-wrapped text message is held for someone unreachable
    And a voice message is held for someone unreachable
    But a file transfer is not held for someone unreachable
    And a delivery receipt is not held for someone unreachable

  @AC-410
  Scenario: With the setting on, an unreachable peer's message is held
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    Then 1 message is queued for bob
    And nothing is waiting in the transport's own queue for bob

  @AC-410
  Scenario: With the setting off, nothing is held and the send goes direct
    Given queueing sends is off
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    Then nothing is queued for bob
    And it is waiting in the transport's own queue for bob instead

  @AC-410
  Scenario: With the setting off, a direct send still keeps its order
    Given queueing sends is off
    And nothing is queued for bob
    When I send bob 3 messages while he is unreachable
    Then nothing is queued for bob
    And the transport holds those 3 for bob in the order they were sent

  # ------------------------------------------------------------------
  # Sending to someone who is offline - the case this exists for
  # ------------------------------------------------------------------

  @AC-053 @AC-410
  Scenario: A message to an offline person is accepted, not refused
    Given queueing sends is on
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "are you there"
    And I press Enter
    Then sending the private message "are you there" to bob is requested

  @AC-053
  Scenario: With nothing to hold it, an offline person's room still refuses
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "are you there"
    And I press Enter
    Then nothing happens

  @AC-053
  Scenario: A command still needs them there, queue or no queue
    Given queueing sends is on
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "/file"
    And I press Enter
    Then nothing happens

  # ------------------------------------------------------------------
  # Order - which is what a pad-wrapped run depends on
  # ------------------------------------------------------------------

  @AC-409
  Scenario: A held run keeps the order it was written in
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 3 messages for bob
    Then 3 messages are queued for bob
    And they come back in the order they were written

  @AC-409
  Scenario: A new message joins the back of what is already waiting
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And I queue 1 message for bob
    Then 3 messages are queued for bob
    And they come back in the order they were written

  @AC-414
  Scenario: A later send never overtakes a queue, even once the link is up
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    And bob's link comes up but his queue has not been drained yet
    And I send bob a message while he is unreachable
    Then 2 messages are queued for bob

  @AC-410
  Scenario: A held message is the sealed payload, not the words
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 1 message for bob
    Then what is queued for bob is byte-identical to what would have been sent

  # ------------------------------------------------------------------
  # Surviving a restart, and being taken exactly once
  # ------------------------------------------------------------------

  @AC-409
  Scenario: What was queued is still there after a restart
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 3 messages for bob
    Then they come back in the order they were written
    And they are still there after a restart

  @AC-409
  Scenario: Taking a peer's queue empties it, so nothing is sent twice
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And bob's queue is taken
    Then nothing is queued for bob
    And nothing is left on disk for bob

  @AC-409
  Scenario: One peer's queue is their own
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And I queue 1 message for carol
    And bob's queue is taken
    Then 1 message is queued for carol

  # ------------------------------------------------------------------
  # The only thing that ever removes a held message
  # ------------------------------------------------------------------

  @AC-413
  Scenario: Nothing ages out - a held message waits as long as it has to
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And those messages were written a year ago
    And bob is still a contact on this machine
    And the queue is swept
    Then 2 messages are queued for bob

  @AC-413
  Scenario: Deleting a contact takes what was held for them
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And I queue 1 message for carol
    And bob is no longer a contact on this machine
    And carol is still a contact on this machine
    And the queue is swept
    Then nothing is queued for bob
    And 1 message is queued for carol

  # ------------------------------------------------------------------
  # What the sender sees
  # ------------------------------------------------------------------

  @AC-412
  Scenario: A held message says so under 'i'
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have sent a message that is being held for bob
    When I move focus to the messages
    And I press the i key
    Then bob's line reads QUEUED
    When I press Escape
    And that message goes out to bob
    And I press the i key
    Then bob's line reads UNDELIVERED
