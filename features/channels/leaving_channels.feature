@US-026
Feature: Leaving a channel

  As a member of a channel
  I want to stop being a member of it without disconnecting entirely
  So that I can step away from a conversation I'm done with while staying
  connected to the rest

  /leave takes no argument - it always targets the currently selected
  channel tab. See docs/PROTOCOL.md section 6.2/7.0.3.

  @AC-109
  Scenario: Leaving a private channel removes its tab
    Given I am connected and viewing a channel
    And I have joined the private channel "secret-room"
    When I select the channel "secret-room"
    And I type "/leave"
    And I press Enter
    And the leave completes
    Then the channel "secret-room" is no longer shown

  @AC-109
  Scenario: Leaving a public channel keeps its tab but marks it not joined
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/leave"
    And I press Enter
    And the leave completes
    Then the channel "general" is still shown
    And the channel "general" is not joined

  @AC-110
  Scenario: Revisiting a left public channel offers to rejoin
    Given I am connected and viewing a channel
    And I have left the channel "general"
    When I press Enter
    Then joining "general" is requested

  @TB-157
  Scenario: Dwelling on a left channel does not silently rejoin it
    Given I am connected and the server has offered a second channel
    And I have left the channel "random"
    When I press the ] key
    And I wait on that tab for longer than the join delay
    Then no join is requested yet
