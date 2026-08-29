@US-006
Feature: Talking to one person privately

  As a connected user
  I want a full-screen room with one other person
  So that we can talk without the rest of the channel

  A private room's history lives only in memory for the session, so the
  sidebar has to make it obvious which conversations exist and which have
  something new in them. See docs/SPEC.md Functionality #3.

  @AC-028 @TB-033
  Scenario: Opening a room from the sidebar and sending into it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I open a private room with bob
    Then a private room with bob is open
    And focus moves to the compose bar
    When I type "just us"
    And I press Enter
    Then sending the private message "just us" to bob is requested

  @AC-028
  Scenario: Escape returns me to the channel
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I press Escape
    Then I am back in the channel view

  @AC-029
  Scenario: A message arriving while I am elsewhere is flagged unread
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "psst"
    Then bob's room is marked unread

  @AC-029
  Scenario: A message arriving in the room I am reading is not flagged unread
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has sent me the private message "hi"
    Then bob's room is not marked unread

  @AC-029
  Scenario: Reopening a room marks it read without throwing away its history
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hey"
    Then bob's room is marked unread
    When I open a private room with bob
    Then bob's room is not marked unread
    And bob's earlier messages are still in the room

  @AC-030
  Scenario: An empty room earns no envelope
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I press Escape
    Then bob shows no envelope in the sidebar

  @AC-030 @TB-034
  Scenario: My own message earns a steady envelope that outlives the room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "hi bob"
    And I press Enter
    And I press Escape
    Then bob's room is not marked unread
    And bob shows a steady envelope in the sidebar

  @AC-030
  Scenario: An unread conversation blinks until it is read
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hey"
    Then bob's envelope blinks
    When I open a private room with bob
    And I press Escape
    Then bob shows a steady envelope in the sidebar

  @AC-031
  Scenario: I cannot open a private room with myself
    Given I am connected and viewing a channel
    And me is in the channel with me
    And bob is in the channel with me
    When I open a private room with me
    Then no private room opens

  # `/leave` is the same act for a conversation of either kind: the
  # channel one drops its whole tab, this drops the room. Messages live
  # only in memory, so either way they are gone with it - what is on disk
  # is the export `autosave_messages` writes, which this never touches.
  @AC-417
  Scenario: /leave in a room closes it and forgets what was said
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    When I open a private room with bob
    And I type "/leave"
    And I press Enter
    Then no private room with bob is open
    And nothing said with bob is left in memory
    And bob is not on the DM selector

  @AC-417
  Scenario: A left room comes back empty when they write again
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    When I open a private room with bob
    And I type "/leave"
    And I press Enter
    And bob has sent me the private message "are you there"
    Then the private room with bob holds 1 message
    And bob is on the DM selector

  @AC-417
  Scenario: Outside a room /leave is still the channel command
    Given I am connected and viewing a channel
    When I type "/leave"
    And I press Enter
    Then leaving the channel "general" is requested
