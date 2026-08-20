@US-004
Feature: Moving between channels

  As a connected user
  I want to tab through the channels I have joined and open private ones by name
  So that I can land on the conversation I care about

  The tab row is exactly the channels I am a member of, so switching tabs
  never joins anything - joining is `/channels` (the public directory) or
  Ctrl+J (by name). See docs/SPEC.md Functionality #2.

  @AC-020
  Scenario: Tabbing moves between the channels I have joined
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    When I press the ] key
    Then the selected channel is "random"
    And no join is requested

  @AC-020
  Scenario: Tabbing backwards wraps around to the last channel
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    When I press the [ key
    Then the selected channel is "random"

  @AC-020 @TB-026
  Scenario: Moving to another channel closes an open private room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the channel already has joined "random"
    And I have opened a private room with bob
    When I press the ] key
    Then no private room is open

  @AC-021
  Scenario: Ctrl+J joins a private channel by name
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    Then the join-channel popup is open
    When I type "secret-room"
    And I press Enter
    Then joining the private channel "secret-room" is requested

  @AC-021
  Scenario: Abandoning the private-channel popup requests nothing
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    And I type "abandoned"
    And I press Escape
    Then the join-channel popup is closed and forgotten

  @AC-021
  Scenario: A blank private-channel name is not a channel
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    And I press Enter
    Then nothing happens
