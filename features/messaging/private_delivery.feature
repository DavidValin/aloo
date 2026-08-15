@US-006
Feature: Delivering a private message

  As a connected user
  I want a one-to-one room with another user
  So that we can talk without the rest of the channel

  A direct message involves no channel at all - it is addressed to a UserId
  and relayed to exactly that connection. See docs/PROTOCOL.md section 7.2.

  @AC-027
  Scenario: A private message reaches its recipient unchanged
    Given a server that anyone may connect to
    And alice has connected
    And bob has connected
    When alice sends the private message "just us" to bob
    Then bob receives the private message "just us" from "alice"
