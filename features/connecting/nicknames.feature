@US-003
Feature: Claiming a unique nickname

  As a user joining a server
  I want my chosen nickname to be mine alone while I am connected
  So that other users can tell who they are talking to

  A nickname is only reserved for as long as its holder is connected. The
  check-and-register happens atomically, so two simultaneous attempts on one
  name cannot both win. See docs/PROTOCOL.md section 5.4. "Connected" is
  never assumed from an open socket alone: the server also frees a
  nickname whose connection goes silent for HEARTBEAT_TIMEOUT with no
  disconnect ever arriving (section 4.1) - covered at the Rust layer
  (`docs/TESTING.md` "Known coverage gaps") rather than here, since proving
  it honestly needs the real timeout to elapse.

  @AC-015 @AC-017
  Scenario: A nickname already in use is refused, and its holder is untouched
    Given a server that anyone may connect to
    And dave has connected
    When someone else tries to connect as "dave"
    Then the nickname is refused, naming "dave"
    And that connection is then closed by the server
    And dave is completely unaffected and can still join "general"

  @AC-016
  Scenario: A nickname frees up the moment its holder leaves
    Given a server that anyone may connect to
    And dave has connected
    When dave disconnects entirely
    Then the nickname "dave" can be claimed again
