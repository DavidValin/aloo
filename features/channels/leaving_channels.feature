@US-026
Feature: Leaving a channel

  As a member of a channel
  I want to stop being a member of it without disconnecting entirely
  So that I can step away from a conversation I'm done with while staying
  connected to the rest

  /leave takes no argument - it always targets the currently selected
  channel tab, and the tab goes away with the membership. A public channel
  is still listed in `/channels` to rejoin from.
  See docs/PROTOCOL.md section 6.2/7.0.3.

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
  Scenario: Leaving a public channel removes its tab but keeps it in the directory
    Given I am connected and viewing a channel
    And the server has announced the public channel "general"
    And bob is in the channel with me
    When I type "/leave"
    And I press Enter
    And the leave completes
    Then the channel "general" is no longer shown
    And the channel "general" is still listed in the directory

  @TB-158
  Scenario: Leaving drops the direct link to a channel-mate I share nothing else with
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/leave"
    And I press Enter
    And the leave completes
    Then there is no reason to keep the link to bob
