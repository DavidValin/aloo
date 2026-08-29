@US-064
Feature: Saying something to someone who is not there

  As a user talking to one person who is offline as often as not
  I want what I send them held until they are reachable
  So that a walkie-talkie to one other person works without both of us being online at once

  Everything here is what `queue_send_messages` turns on, and every
  layering has to behave the same way under it: an ordinary `pqhybrid`
  envelope, a pad wrapped inside one (`pqhybrid_otp`), and a pad-only
  pair with no readable identity between them (`direct_otp`) - the same
  three `features/encryption/message_encryption.feature` covers, with or
  without a server. With the switch off nothing is held at all and, under
  a pad, nothing is even encrypted - a spent pad position with nowhere to
  go is worse than a refusal you can see.

  What is held is exactly what would have gone on the wire, still sealed.
  Nothing ages out and nothing is evicted; the one thing that removes a
  held message is the contact it was sealed for no longer being on this
  machine. See docs/SPEC.md Functionality #34; the Ctrl+S switch itself
  is features/settings/settings_popup.feature.


  # ------------------------------------------------------------------
  # The whole matrix: the switch x whether they are there x the layering,
  # with and without a reachable server.
  #
  # The server dimension is a tag rather than a step, and deliberately so:
  # none of this consults a server. A send travels on a punched link, and
  # whether a server happens to be reachable changes only how the two
  # found each other - which is the claim each @with_server /
  # @without_reachable_server pair below is making.
  # ------------------------------------------------------------------

  # --- queueing on, they are there -------------------------------------

  @AC-410 @pqhybrid @with_server
  Scenario: On, present, sealed envelope, server reachable
    Given queueing sends is on
    And bob is reachable
    When I send bob a message
    Then it went straight out to bob, held nowhere

  @AC-410 @pqhybrid @without_reachable_server
  Scenario: On, present, sealed envelope, no reachable server
    Given queueing sends is on
    And bob is reachable
    When I send bob a message
    Then it went straight out to bob, held nowhere

  @AC-418 @pqhybrid_otp @with_server
  Scenario: On, present, pad inside an envelope, server reachable
    Given queueing sends is on
    And bob is reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    And the queue for "alice-bob" is pumped
    Then the front of it went out, and only the front
    And 1 sealed pad message is still waiting for its acknowledgement

  @AC-418 @pqhybrid_otp @without_reachable_server
  Scenario: On, present, pad inside an envelope, no reachable server
    Given queueing sends is on
    And bob is reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    And the queue for "alice-bob" is pumped
    Then the front of it went out, and only the front

  @AC-418 @direct_otp @with_server
  Scenario: On, present, pad only, server reachable
    Given queueing sends is on
    And bob is reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    And the queue for "alice-bob" is pumped
    Then the front of it went out, and only the front

  @AC-418 @direct_otp @without_reachable_server
  Scenario: On, present, pad only, no reachable server
    Given queueing sends is on
    And bob is reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    And the queue for "alice-bob" is pumped
    Then the front of it went out, and only the front

  # --- queueing on, they are away --------------------------------------

  @AC-410 @pqhybrid @with_server
  Scenario: On, away, sealed envelope, server reachable
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for bob
    When I send bob a message
    Then 1 message is queued for bob
    And nothing is waiting in the transport's own queue for bob

  @AC-410 @pqhybrid @without_reachable_server
  Scenario: On, away, sealed envelope, no reachable server
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for bob
    When I send bob a message
    Then 1 message is queued for bob

  @AC-418 @pqhybrid_otp @with_server
  Scenario: On, away, pad inside an envelope, server reachable
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    Then 1 pad message is queued for "alice-bob"

  @AC-418 @pqhybrid_otp @without_reachable_server
  Scenario: On, away, pad inside an envelope, no reachable server
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    Then 1 pad message is queued for "alice-bob"

  @AC-418 @direct_otp @with_server
  Scenario: On, away, pad only, server reachable
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    Then 1 pad message is queued for "alice-bob"

  @AC-418 @direct_otp @without_reachable_server
  Scenario: On, away, pad only, no reachable server
    Given queueing sends is on
    And bob is not reachable
    And nothing is queued for the contact "alice-bob"
    When I write a pad message for "alice-bob"
    Then 1 pad message is queued for "alice-bob"

  # --- queueing off, they are there ------------------------------------
  #
  # With them present the switch changes nothing at all: there was never
  # anything to hold. That is the point of asserting it rather than
  # assuming it.

  @AC-410 @pqhybrid @with_server
  Scenario: Off, present, sealed envelope, server reachable
    Given queueing sends is off
    And bob is reachable
    When I send bob a message
    Then it went straight out to bob, held nowhere

  @AC-410 @pqhybrid @without_reachable_server
  Scenario: Off, present, sealed envelope, no reachable server
    Given queueing sends is off
    And bob is reachable
    When I send bob a message
    Then it went straight out to bob, held nowhere

  @AC-421 @pqhybrid_otp @with_server
  Scenario: Off, present, pad inside an envelope, server reachable
    Given queueing sends is off
    And bob is reachable
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    Then an offline peer's send is accepted for holding

  @AC-421 @pqhybrid_otp @without_reachable_server
  Scenario: Off, present, pad inside an envelope, no reachable server
    Given queueing sends is off
    And bob is reachable
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    Then an offline peer's send is accepted for holding

  @AC-421 @direct_otp @with_server
  Scenario: Off, present, pad only, server reachable
    Given queueing sends is off
    And bob is reachable
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    Then an offline peer's send is accepted for holding

  @AC-421 @direct_otp @without_reachable_server
  Scenario: Off, present, pad only, no reachable server
    Given queueing sends is off
    And bob is reachable
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    Then an offline peer's send is accepted for holding

  # --- queueing off, they are away -------------------------------------
  #
  # The half that matters. An ordinary envelope falls back to the
  # transport's own minute-long queue and is reported if it expires. A pad
  # message is stopped before `otp --encrypt` runs at all, which is what
  # keeps a pad position from being spent on something with nowhere to go.

  @AC-410 @pqhybrid @with_server
  Scenario: Off, away, sealed envelope, server reachable
    Given queueing sends is off
    And bob is not reachable
    And nothing is queued for bob
    When I send bob a message
    Then nothing is queued for bob
    And it is waiting in the transport's own queue for bob instead

  @AC-410 @pqhybrid @without_reachable_server
  Scenario: Off, away, sealed envelope, no reachable server
    Given queueing sends is off
    And bob is not reachable
    And nothing is queued for bob
    When I send bob a message
    Then nothing is queued for bob
    And it is waiting in the transport's own queue for bob instead

  @AC-421 @pqhybrid_otp @with_server
  Scenario: Off, away, pad inside an envelope, server reachable
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    Then an offline peer's send is refused before anything is encrypted

  @AC-421 @pqhybrid_otp @without_reachable_server
  Scenario: Off, away, pad inside an envelope, no reachable server
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    Then an offline peer's send is refused before anything is encrypted

  @AC-421 @direct_otp @with_server
  Scenario: Off, away, pad only, server reachable
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    Then an offline peer's send is refused before anything is encrypted

  @AC-421 @direct_otp @without_reachable_server
  Scenario: Off, away, pad only, no reachable server
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    Then an offline peer's send is refused before anything is encrypted

  # ------------------------------------------------------------------
  # What is held, and what is not
  # ------------------------------------------------------------------

  @AC-408 @pqhybrid
  Scenario: Text and voice are held, files are not
    Given queueing sends is on
    Then a text message is held for someone unreachable
    And a voice message is held for someone unreachable
    But a pad-wrapped message is held in the pad queue instead
    And a file transfer is not held for someone unreachable
    And a delivery receipt is not held for someone unreachable

  @AC-410 @pqhybrid
  Scenario: With the setting on, an unreachable peer's message is held
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    Then 1 message is queued for bob
    And nothing is waiting in the transport's own queue for bob

  @AC-410 @pqhybrid
  Scenario: With the setting off, nothing is held and the send goes direct
    Given queueing sends is off
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    Then nothing is queued for bob
    And it is waiting in the transport's own queue for bob instead

  @AC-410 @pqhybrid
  Scenario: With the setting off, a direct send still keeps its order
    Given queueing sends is off
    And nothing is queued for bob
    When I send bob 3 messages while he is unreachable
    Then nothing is queued for bob
    And the transport holds those 3 for bob in the order they were sent

  # ------------------------------------------------------------------
  # What actually deletes a held message
  #
  # Handing content to the transport is not delivering it. The link can
  # die mid-flight - the frame is given up on and nothing else would ever
  # re-send it - and the process can be killed. Only the peer saying it
  # arrived makes the copy on disk redundant.
  # ------------------------------------------------------------------

  @AC-422 @pqhybrid
  Scenario: A drained message is still held until it is acknowledged
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    Then 1 message is queued for bob
    When bob's link comes up and his queue is drained
    Then 1 message is queued for bob
    When bob acknowledges the held message 0
    Then nothing is queued for bob

  @AC-422 @pqhybrid
  Scenario: A message nobody ever acknowledged is kept, not lost
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    And bob's link comes up and his queue is drained
    Then 1 message is queued for bob
    When bob's link comes up and his queue is drained
    Then 1 message is queued for bob

  @AC-422 @pqhybrid
  Scenario: Only the acknowledged message goes, and the rest wait their turn
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob 3 messages while he is unreachable
    And bob's link comes up and his queue is drained
    And bob acknowledges the held message 1
    Then 2 messages are queued for bob

  # ------------------------------------------------------------------
  # Order - which is what a pad-wrapped run depends on
  # ------------------------------------------------------------------

  @AC-409 @pqhybrid
  Scenario: A held run keeps the order it was written in
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 3 messages for bob
    Then 3 messages are queued for bob
    And they come back in the order they were written

  @AC-409 @pqhybrid
  Scenario: A new message joins the back of what is already waiting
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And I queue 1 message for bob
    Then 3 messages are queued for bob
    And they come back in the order they were written

  @AC-414 @pqhybrid
  Scenario: A later send never overtakes a queue, even once the link is up
    Given queueing sends is on
    And nothing is queued for bob
    When I send bob a message while he is unreachable
    And bob's link comes up but his queue has not been drained yet
    And I send bob a message while he is unreachable
    Then 2 messages are queued for bob

  @AC-410 @pqhybrid
  Scenario: A held message is the sealed payload, not the words
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 1 message for bob
    Then what is queued for bob is byte-identical to what would have been sent

  # ------------------------------------------------------------------
  # Surviving a restart, and being taken exactly once
  # ------------------------------------------------------------------

  @AC-409 @pqhybrid
  Scenario: What was queued is still there after a restart
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 3 messages for bob
    Then they come back in the order they were written
    And they are still there after a restart

  @AC-409 @pqhybrid
  Scenario: Taking a peer's queue empties it, so nothing is sent twice
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And bob's queue is taken
    Then nothing is queued for bob
    And nothing is left on disk for bob

  @AC-409 @pqhybrid
  Scenario: One peer's queue is their own
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And I queue 1 message for carol
    And bob's queue is taken
    Then 1 message is queued for carol

  # ------------------------------------------------------------------
  # Under a one-time pad: sealing is spending, so the queue holds
  # ciphertext and drains one message per acknowledgement
  # ------------------------------------------------------------------

  @AC-418 @pqhybrid_otp
  Scenario: Pad messages queue in the order they were sealed
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 4 pad messages for "alice-bob"
    Then 4 pad messages are queued for "alice-bob"
    And they come back in the order they were sealed

  @AC-418 @pqhybrid_otp
  Scenario: The front stays put until its own acknowledgement retires it
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 3 pad messages for "alice-bob"
    Then the next pad message for "alice-bob" is sequence 0
    And reading it again does not consume it
    When that message is acknowledged
    Then the next pad message for "alice-bob" is sequence 1
    And 2 pad messages are queued for "alice-bob"

  @AC-418 @pqhybrid_otp
  Scenario: A spent pad position survives a restart
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 3 pad messages for "alice-bob"
    And that message is acknowledged
    Then after a restart 2 pad messages are queued for "alice-bob"
    And after a restart the next pad message for "alice-bob" is sequence 1

  @AC-418 @pqhybrid_otp
  Scenario: What is queued is the sealed ciphertext, never the words
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 1 pad message for "alice-bob"
    Then what is queued for "alice-bob" is byte-identical to what was sealed

  # A pad-only pair has no readable identity to seal an envelope to, so
  # their messages are the pad and nothing else - and they are queued on
  # exactly the same terms, which is the point of asserting it separately.
  @AC-418 @direct_otp @without_reachable_server
  Scenario: A pad-only pair's messages queue the same way
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 2 pad-only messages for "alice-bob"
    Then 2 pad messages are queued for "alice-bob"
    And they come back in the order they were sealed

  @AC-419 @pqhybrid_otp
  Scenario: A pad queue is discarded only when the contact's keys are gone
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 2 pad messages for "alice-bob"
    And I seal 1 pad message for "alice-carol"
    And the contact "alice-bob" is still on this machine
    And the contact "alice-carol" is still on this machine
    And the pad queue is swept
    Then 2 pad messages are queued for "alice-bob"
    When the contact "alice-bob" is no longer on this machine
    And the pad queue is swept
    Then nothing is queued for the contact "alice-bob"
    And 1 pad message is queued for "alice-carol"
    And no queue file is left for "alice-bob"

  # Sealing spends the pad, and a spend cannot be taken back - so the queue
  # has to say whether it actually took the sealed bytes. Reporting a
  # refusal as success would lose the only copy of a message that can never
  # be re-sealed, and leave this end's pad one position ahead of theirs.
  @AC-421 @pqhybrid_otp
  Scenario: The pad queue says whether it took a sealed message
    Given queueing sends is on
    When I try to queue a sealed pad message for the contact "alice-bob"
    Then the queue says it took it
    When I try to queue a sealed pad message for the contact "../escape"
    Then the queue says it did not take it, so the caller can send it instead
    And nothing is queued for the contact "../escape"

  # A voice message under the pad is held like a text one, with one
  # wrinkle: it is sealed when it is recorded rather than when the peer
  # accepts it, so nothing readable waits on disk while they are away -
  # and because it cannot travel until they accept, its position is
  # reserved and later messages wait behind it.
  @AC-423 @direct_otp @without_reachable_server
  Scenario: A voice message for someone who is away is sealed when it is recorded
    Given alice and bob reach each other directly and hold a pad for each other
    And queued sends are on for that pair
    And bob has become unreachable for alice
    When alice records a voice message for bob
    Then both of that voice message's pad positions are already spent
    And what waits on disk for bob is ciphertext, not the recording
    And the offer's position comes before the recording's

  @AC-423 @direct_otp @without_reachable_server
  Scenario: A message written after a queued voice message waits behind it
    Given alice and bob reach each other directly and hold a pad for each other
    And queued sends are on for that pair
    And bob has become unreachable for alice
    When alice records a voice message for bob
    Then the recording waits its turn in the queue
    And a message written after it does not go out ahead of it

  # Several voice messages stack the way anything else does. Each seal's
  # ciphertext is captured into the queue at the only moment it exists -
  # the CLI's own safety copy is one deep and holds just the newest seal,
  # so nothing here ever depends on it.
  @AC-431 @direct_otp @without_reachable_server
  Scenario: Three voice messages stack in the queue, each with its own ciphertext
    Given alice and bob reach each other directly and hold a pad for each other
    And queued sends are on for that pair
    And bob has become unreachable for alice
    When alice records a voice message for bob
    And alice records a voice message for bob
    And alice records a voice message for bob
    Then six entries wait, offers and recordings alternating in order
    And each recording waits as its own ciphertext file

  @AC-423 @direct_otp @without_reachable_server
  Scenario: A recording larger than the key left is refused before anything is spent
    Given alice and bob reach each other directly and hold a pad for each other
    And queued sends are on for that pair
    And bob has become unreachable for alice
    When alice records a voice message larger than the key she has left
    Then the recording is refused, naming what is left
    And no pad was spent on it

  @AC-419 @pqhybrid_otp
  Scenario: Draining the last one leaves no file behind
    Given queueing sends is on
    And nothing is queued for the contact "alice-bob"
    When I seal 1 pad message for "alice-bob"
    And that message is acknowledged
    Then nothing is queued for the contact "alice-bob"
    And no queue file is left for "alice-bob"

  # ------------------------------------------------------------------
  # The only thing that ever removes a held message
  # ------------------------------------------------------------------

  @AC-413 @pqhybrid
  Scenario: Nothing ages out - a held message waits as long as it has to
    Given queueing sends is on
    And nothing is queued for bob
    When I queue 2 messages for bob
    And those messages were written a year ago
    And bob is still a contact on this machine
    And the queue is swept
    Then 2 messages are queued for bob

  @AC-413 @pqhybrid
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
  # Sending to someone who is offline - the case this exists for
  # ------------------------------------------------------------------

  @AC-053 @AC-410 @pqhybrid
  Scenario: A message to an offline person is accepted, not refused
    Given queueing sends is on
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "are you there"
    And I press Enter
    Then sending the private message "are you there" to bob is requested

  @AC-053 @pqhybrid
  Scenario: With nothing to hold it, an offline person's room still refuses
    Given queueing sends is off
    And I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "are you there"
    And I press Enter
    Then nothing happens

  @AC-053 @pqhybrid
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
  # What the sender sees
  # ------------------------------------------------------------------

  @AC-412 @pqhybrid
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

  # ------------------------------------------------------------------
  # Over a real connection: two real sessions, a real server, real
  # sockets. Two bugs got through the simulated scenarios above and only
  # showed up here - a send to a peer whose rotating key had been dropped
  # could not be sealed at all and vanished without a word, and asking
  # the server to signal a link to somebody who had left surfaced as a
  # red error on screen.
  # ------------------------------------------------------------------

  @AC-410 @AC-420 @AC-422 @pqhybrid @with_server
  Scenario: A message written while they are away reaches them when they return
    Given a server that anyone may connect to
    And alice joins the server for real, into "general"
    And bob joins the server for real, into "general"
    And bob opens the private room with alice for real
    And alice sends bob the private message "hello while you are here" for real
    And bob's screen shows "hello while you are here" within 30 seconds
    And bob has gone offline for real
    When alice sends bob the private message "while you were out" for real
    Then alice's screen never showed "failed"
    And alice's screen never showed "unknown recipient"
    And alice has 1 message held for bob
    When bob comes back for real, into "general"
    And bob opens the private room with alice for real
    Then bob's screen shows "while you were out" within 40 seconds
    # And his acknowledgement is what finally clears it from her disk -
    # nothing before that point was allowed to (AC-422).
    And alice has 0 messages held for bob

  @AC-410 @AC-420 @AC-422 @pqhybrid @with_server
  Scenario: Several messages written while they are away are all kept
    Given a server that anyone may connect to
    And alice joins the server for real, into "general"
    And bob joins the server for real, into "general"
    And bob opens the private room with alice for real
    And alice sends bob the private message "hello while you are here" for real
    And bob has gone offline for real
    When alice sends bob the private message "first while out" for real
    And alice sends bob the private message "second while out" for real
    Then alice's screen never showed "unknown recipient"
    And alice has 2 messages held for bob
    When bob comes back for real, into "general"
    And bob opens the private room with alice for real
    Then bob's screen shows "first while out" within 40 seconds
    And bob's screen shows "second while out" within 40 seconds
    And bob's screen shows "first while out" above "second while out"
    And alice has 0 messages held for bob
