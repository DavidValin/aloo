@US-016
Feature: Moving around the connected screen

  As a connected user
  I want to move keyboard focus between the parts of the screen
  So that I can reach the sidebar, the log and the compose bar without a mouse

  @AC-062
  Scenario: Tab cycles through the three areas and back
    Given I am connected and viewing a channel
    Then focus is still on the compose
    When I press Tab
    Then focus moves to the sidebar
    When I press Tab
    Then focus moves to the log
    When I press Tab
    Then focus moves to the compose

  @AC-063
  Scenario: Up and Down move the selected user, wrapping around
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And focus is on the sidebar
    When I press Up
    Then the selected user is at position 2
    When I press Down
    Then the selected user is at position 0

  @AC-237
  Scenario: A popup replaces the view behind it
    Given I am connected and viewing a channel
    And the channel log is full of messages
    When I press Ctrl+J
    Then the join-channel popup is open
    And nothing of the view behind the popup shows through it
