@US-063
Feature: Hearing it when someone writes your name

  As a user with a channel open in a terminal I am not looking at
  I want a sound when someone writes @<my nickname>
  So that I notice a message meant for me without watching every channel go by

  A mention is a whole word, and case-sensitive - the server tells bob and
  Bob apart, so a ping meant for one must never sound for the other. See
  docs/SPEC.md Functionality #33.

  @AC-403
  Scenario: Being named
    Given I am connected and viewing a channel
    Then "@me are you there?" mentions me
    And "hey @me" mentions me
    And "well, @me, no" mentions me
    And "(@me)" mentions me

  @AC-403
  Scenario: Not being named
    Given I am connected and viewing a channel
    Then "nothing to see here" does not mention me
    And "me without the at" does not mention me
    And "write to bob@me.example" does not mention me
    And "@meredith said so" does not mention me
    And "@me-too is someone else" does not mention me
    And "@Me hello" does not mention me

  @AC-403
  Scenario: Only words can name anyone
    Given I am connected and viewing a channel
    Then an arriving voice message never mentions me
