@US-022
Feature: Sending a voice message from anywhere via the global shortcut

  As a connected user
  I want to hold a systemwide shortcut and have my voice stream to whatever
  I was last looking at in aloo, even while some other window is focused
  So that I don't have to switch back to the terminal just to talk

  Bound to Ctrl+Alt+P by default, configurable in ~/.aloo/settings
  (global_ptt_shortcut, global_ptt_enabled). Reuses the exact same
  start/stop-a-live-stream path as holding Space (see push_to_talk.feature,
  US-007) - the only difference is what triggers it and that it has no
  notion of this app's own terminal focus. See docs/SPEC.md Functionality #4.

  @AC-089
  Scenario: Holding the global shortcut streams to the channel I was viewing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I hold Ctrl+Alt+P
    Then a voice message starts streaming to the channel, addressed to bob
    When I release Ctrl+Alt+P
    Then the voice message is sent

  @AC-089
  Scenario: Holding the global shortcut in a private room streams to that person instead
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I hold Ctrl+Alt+P
    Then a voice message starts streaming privately to bob
    When I release Ctrl+Alt+P
    Then the voice message is sent

  @AC-090
  Scenario: Holding the global shortcut with nowhere to send does not record
    Given I am connected but have not joined any channel
    When I hold Ctrl+Alt+P
    Then no recording starts

  @AC-091
  Scenario: The global shortcut cannot stop a recording Space itself started
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the log
    When I hold Space
    And I release Ctrl+Alt+P
    Then the recording carries on regardless
