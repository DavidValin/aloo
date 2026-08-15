@US-005
Feature: Delivering a message to the people it was addressed to

  As a member of a channel
  I want to type a message and have every other member receive it
  So that we can hold a conversation

  The sender addresses each recipient individually with their own separately
  encrypted copy; the server relays opaque bytes it cannot read and drops any
  addressee who is not a member. See docs/PROTOCOL.md sections 7.1 and 8.

  @AC-024
  Scenario: A channel message reaches the member it was addressed to, unchanged
    Given a server that anyone may connect to
    And alice has connected
    And bob has connected
    And alice and bob are both in the channel "general"
    When alice sends "hi bob" to bob in "general"
    Then bob receives the message "hi bob" from "alice" in "general"
