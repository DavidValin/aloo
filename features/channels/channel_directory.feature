@US-004
Feature: The public channel directory

  As a connected user
  I want one place listing every public channel the server offers
  So that I can see what exists and join only the rooms I actually want

  Connecting joins exactly one channel, "the-hall"; the tab row is the
  channels I am a member of, and everything else the server offers lives
  behind `/channels`. See docs/PROTOCOL.md section 6.3.

  @AC-174
  Scenario: Connecting joins only the-hall, however much else is on offer
    Given a server offering "the-hall" and "random"
    When the client applies the connect-time channel list
    Then joining "the-hall" is requested
    And the channel "random" is not on the channel selector

  @TB-206
  Scenario: A public channel I have not joined is listed but not on the selector
    Given I am connected and viewing a channel
    And the server has announced the public channel "random"
    Then the channels modal lists "random"
    And the channel "random" is not on the channel selector

  @AC-172
  Scenario: /channels lists every public channel, mine marked as mine
    Given I am connected and viewing a channel
    And the server has announced the public channel "general"
    And the server has announced the public channel "random"
    When I type "/channels"
    And I press Enter
    Then the channels modal is open
    And the channels modal lists "general"
    And the channels modal lists "random"
    And the channels modal shows "general" as one of mine
    And the channels modal shows "random" as one I have not joined

  @AC-172
  Scenario: Escape closes the directory without joining anything
    Given I am connected and viewing a channel
    And the server has announced the public channel "random"
    When I type "/channels"
    And I press Enter
    And I press Escape
    Then the channels modal is closed
    And no join is requested

  @AC-173
  Scenario: Enter on a channel in the directory joins it
    Given I am connected and viewing a channel
    And the server has announced the public channel "random"
    When I type "/channels"
    And I press Enter
    And I press Down
    And I press Enter
    Then joining "random" is requested
    And the channels modal is closed
