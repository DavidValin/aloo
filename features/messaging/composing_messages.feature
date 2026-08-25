@US-005
Feature: Composing a message to the channel

  As a member of a channel
  I want to type a message and send it with one key
  So that talking is not a ceremony

  @AC-025 @TB-028
  Scenario: Typing and pressing Enter sends to everyone else in the channel
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When I type "hello all"
    And I press Enter
    Then sending "hello all" to the channel is requested, addressed to bob and carol
    And my message is shown in the channel log as mine
    And the compose bar is empty

  @AC-026
  Scenario: An empty compose bar sends nothing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I press Enter
    Then nothing is sent

  @AC-026
  Scenario: Typing before joining a channel keeps the text rather than losing it
    Given I am connected but have not joined any channel
    When I type "too early"
    And I press Enter
    Then nothing is sent
    And the compose bar holds "too early"

  @AC-326
  Scenario: Pasting a multi-line block sends it as one message, newlines and all
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When I paste "line one" and "line two" as one block
    Then sending "line one" and "line two" as one message to the channel is requested, addressed to bob and carol
    And the compose bar is empty

  @TB-252
  Scenario: Typed text stops accepting characters past the length cap
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type a block of 10001 characters
    Then the compose bar holds exactly 10000 characters
