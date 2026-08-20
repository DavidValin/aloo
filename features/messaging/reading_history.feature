@US-015
Feature: Reading back message history

  As a user catching up
  I want to scroll back without being yanked around by new traffic
  So that I can read history while the conversation continues

  The rule is "follow only if already following": a view sitting on the newest
  message keeps up with new arrivals, and a view scrolled back into history
  stays exactly where it was put. See docs/SPEC.md "Connected UI".

  @AC-059
  Scenario: A channel opens on its newest message
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 5 messages
    Then the newest message is selected

  @AC-059
  Scenario: A private room opens on its newest message
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me 3 private messages
    When I open a private room with bob
    Then a private room with bob is open
    And the newest message is selected

  @AC-060
  Scenario: A new message pulls the view along when I am already at the bottom
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 3 messages
    Then message 2 is selected
    When 1 more messages arrive
    Then message 3 is selected

  @AC-060
  Scenario: A new message leaves a scrolled-back reader where they are
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 3 messages
    And focus is on the log
    When I press Home
    Then the oldest message is selected
    When 1 more messages arrive
    Then the oldest message is selected

  @AC-061
  Scenario: Up and Down move one message and stop at the ends
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 2 messages
    And focus is on the log
    When I press Up
    Then the oldest message is selected
    When I press Up
    Then the oldest message is selected
    When I press Down
    And I press Down
    Then message 1 is selected

  @AC-061
  Scenario: Page and Home/End keys jump further
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds more than a page of messages
    And focus is on the log
    Then the newest message is selected
    When I press Home
    Then the oldest message is selected
    When I press PageDown
    Then the selection sits one page from the oldest
    When I press End
    Then the newest message is selected
    When I press PageUp
    Then the selection sits one page from the newest

  @AC-190
  Scenario: The scroll keys reach the log straight from the compose bar
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds more than a page of messages
    And focus is on the compose
    When I press Up
    Then the selection is 1 entries below the newest
    And focus is still on the compose
    When I press PageUp
    Then the selection is 11 entries below the newest
    When I press PageDown
    Then the selection is 1 entries below the newest
    When I press Down
    Then the newest message is selected

  @AC-190
  Scenario: Scrolling from the compose bar does not type into the message
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds more than a page of messages
    And focus is on the compose
    When I press Up
    Then the compose bar is empty

  @AC-191
  Scenario: A log that overflows its pane shows a scrollbar
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 40 messages
    Then the message pane shows a scrollbar

  @AC-191
  Scenario: A log that fits its pane shows no scrollbar
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 2 messages
    Then the message pane shows no scrollbar

  @TB-211
  Scenario: The scrollbar thumb tracks the viewport
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 40 messages
    Then the scrollbar thumb sits at the bottom of its track
    When I move focus to the log
    And I press Home
    Then the scrollbar thumb sits at the top of its track

  @TB-109
  Scenario: The viewport follows the selection rather than pinning the top
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the message log holds 40 messages
    Then the newest message is visible and the oldest has scrolled away
    When I move focus to the log
    And I press Home
    Then the oldest message is visible and the newest has scrolled away
