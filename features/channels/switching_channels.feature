@US-004
Feature: Moving between channels

  As a connected user
  I want to tab through the channels on offer and open private ones by name
  So that I can land on the conversation I care about without joining every
  tab I pass through

  Selecting a tab and joining it are deliberately separate: the selection
  moves at once so you can flick past several, and the join only happens once
  you settle. See docs/SPEC.md Functionality #2.

  @AC-020
  Scenario: Tabbing to a channel selects it without joining it
    Given I am connected and the server has offered a second channel
    And the channel already has joined "general"
    When I press the ] key
    Then the selected channel is "random"
    And "random" has not been joined yet
    When I check the dwell timer straight away
    Then no join is requested yet

  @AC-020
  Scenario: Settling on a channel joins it
    Given I am connected and the server has offered a second channel
    When I press the ] key
    And I wait on that tab for longer than the join delay
    Then joining "random" is requested

  @AC-020
  Scenario: Tabbing backwards wraps around to the last channel
    Given I am connected and the server has offered a second channel
    And the channel already has joined "general"
    When I press the [ key
    Then the selected channel is "random"

  @AC-020 @TB-026
  Scenario: Moving to another channel closes an open private room
    Given I am connected and the server has offered a second channel
    And the channel already has joined "general"
    And bob is in the channel with me
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
