@US-006
Feature: Delivering a private message

  As a connected user
  I want a one-to-one room with another user
  So that we can talk without the rest of the channel

  A direct message involves no channel at all - it is addressed to a UserId
  and delivered directly over a peer-to-peer link punched between the two
  clients, never through the server. See docs/PROTOCOL.md section 7.2 and
  "Direct peer-to-peer transport".

  @AC-027 @AC-100
  Scenario: A private message reaches its recipient unchanged
    Given a server that anyone may connect to
    And alice has connected
    And bob has connected
    When alice sends the private message "just us" to bob
    Then bob receives the private message "just us" from "alice"
