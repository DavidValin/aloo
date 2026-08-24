@US-047
Feature: Open a link straight from a message

  As a user reading a message that contains a URL
  I want that link to stand out and to open in my default browser
  So that following it never means retyping or copy-pasting it by hand

  @AC-285
  Scenario: A link in a message is shown in blue and underlined
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob sends the channel message "see https://example.com/x for details"
    Then the link "https://example.com/x" is shown in blue and underlined

  @AC-286
  Scenario: Ctrl+O opens the focused message's link
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob sends the channel message "see https://example.com/x for details"
    When I press Ctrl+O
    Then the browser opens "https://example.com/x"

  @AC-286
  Scenario: Ctrl+O does nothing on a message with no link
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob sends the channel message "hello there"
    When I press Ctrl+O
    Then nothing happens
