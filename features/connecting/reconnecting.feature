@US-040
Feature: Getting back onto the server

  As someone whose network drops while aloo is running
  I want aloo to get itself back on the server and show me where it is up to
  So that I stay visible to everyone, including people who connect while I am away

  Losing the server never ends a conversation - content is peer-to-peer and
  the direct links carry on without it - but it does end presence: the
  nickname is freed, everyone is told this client went offline, and nobody
  who connects afterwards is ever told it exists. Left there, messages keep
  arriving from someone who is in nobody's user list. See docs/PROTOCOL.md
  4.2 and docs/SPEC.md Functionality #19.

  @AC-222
  Scenario: The first attempt is immediate, and every failure widens the wait
    Then the wait before the first attempt is no wait at all
    And the wait after 1 failed attempt is 5 seconds
    And the wait after 2 failed attempts is 10 seconds
    And the wait after 3 failed attempts is 20 seconds
    And the wait never grows past 30 seconds, however many have failed

  @AC-223
  Scenario: The header says which of those is happening
    Given I am connected and viewing a channel
    Then the server state reads "Connected to server!" in green
    When the server connection is lost
    Then the server state reads "Reconnecting..." in red
    When 1 attempt has failed and the next is 5 seconds away
    Then the server state reads "Reconnecting in 5s..." in red
    When 3 attempts have failed and the next is 30 seconds away
    Then the server state reads "Server down (reconnecting in 30 sec...)" in red

  @AC-223
  Scenario: It reads first, and the selectors line up with the messages below them
    Given I am connected and viewing a channel
    Then the server state is the first thing on the header row
    And the channel selector starts where the message list starts

  @AC-223
  Scenario: A state too long to fit moves the selectors instead of losing its number
    Given I am connected and viewing a channel
    When 3 attempts have failed and the next is 30 seconds away
    Then the whole countdown is still readable
    And the selectors have moved aside for it

  @AC-224
  Scenario: With no server there is nothing to count down at
    Given I am connected and viewing a channel
    And I am running with no server at all
    Then the server state reads "No server mode" in white
    When a direct punch to bob is in flight
    Then the server state reads "No server mode (punching)" in white

  @AC-226
  Scenario: A nickname the dead connection still holds is retried, not surrendered
    Given a server that anyone may connect to
    And alice has connected
    Then reconnecting as "alice" is refused while that connection holds the name
    And the refusal is an ordinary failure, scheduled for another attempt

  @AC-225
  @AC-227
  Scenario: A client the server gave up on puts itself back in the member list
    Given a server that gives up on a silent client after 1 second
    And alice is running a session on it, joined to "general"
    When the server gives up on alice's connection
    Then bob, connecting afterwards, is told alice is in "general"
