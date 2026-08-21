@US-010
Feature: Waiting for a rotating peer's next key

  As a user messaging a peer whose key rotates during the session
  I want messages typed before their next key arrives to be held, then sent
  once it does
  So that nothing is lost or silently dropped while their key is mid-rotation

  Only pq_hybrid rotates its encryption keys during a session. A message
  typed for such a peer while their key is stale is queued rather than
  dropped, and the whole queue flushes, in order, the moment their next key
  arrives. Waiting is bounded, though: a key that never becomes usable ends
  with the message given up on and said so, rather than held forever. See
  docs/PROTOCOL.md sections 13.10 and 11.1.

  @AC-045 @TB-080
  Scenario: Messages typed before a peer's next key arrives are held, then sent in order
    Given bob uses a rotating key and I have already used his current key
    When I type "first" and then "second" to him
    Then both messages are held, not sent
    When bob's next key arrives
    Then they go out together, "first" before "second"
    And his key is stale again until the next rotation

  @AC-234
  Scenario: A message held for a key that never comes is eventually given up on
    Given bob uses a rotating key and I have already used his current key
    When I type "first" and then "second" to him
    And every rotation hands them back but none of them can be sent
    Then both are given up on rather than held forever
    And each names the row it was shown on, so it can be marked failed
