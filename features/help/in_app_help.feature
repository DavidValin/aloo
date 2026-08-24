@US-014
Feature: Getting help without leaving the app

  As a user who has forgotten a keybinding
  I want a help overlay available from anywhere
  So that I do not have to leave the app to look something up

  Help is checked before any other key handling, so it works from any view or
  mode. Esc deliberately does not close it: Esc already means "close the
  private room" when help is not open, and the overlay does not try to
  disambiguate the two. See docs/SPEC.md Functionality #7.

  @AC-056
  Scenario: Ctrl+H opens and closes the overlay
    Given I am connected and viewing a channel
    When I press Ctrl+H
    Then the help overlay is open
    When I press Ctrl+H
    Then the help overlay is closed

  @AC-056
  Scenario: The shortcut works in either letter case
    Given I am connected and viewing a channel
    When I press Ctrl+Shift+H
    Then the help overlay is open

  @AC-056
  Scenario: Help opens from inside a private room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I press Ctrl+H
    Then the help overlay is open

  @AC-056
  Scenario: Help opens even with the join-channel popup already up
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    Then the join-channel popup is open
    When I press Ctrl+H
    Then the help overlay is open

  @AC-057 @TB-108
  Scenario: The overlay covers the things people forget
    Given I am connected and viewing a channel
    And the help overlay is open
    Then the help overlay explains private channels, voice, files and the tags
    And the help popup shows its longest line unclipped
    And the help popup covers the whole screen, the compose bar included
    Then scrolling to the bottom reveals contacts and keys

  @AC-058
  Scenario: A reminder that help exists is always on screen
    Given I am connected and viewing a channel
    Then the help hint sits at the top right

  @TB-106
  Scenario: While help is open it swallows every other key
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the sidebar
    And the help overlay is open
    When I press Tab
    Then nothing happens
    And focus is still on the sidebar
    And the help overlay is open
    When I type "hello"
    Then my typing does not reach the compose bar

  @TB-106
  Scenario: Escape closes help without touching the room underneath it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And the help overlay is open
    When I press Escape
    Then the help overlay is closed
    And the private room underneath is untouched

  @TB-126
  Scenario: The overlay scrolls, and always reopens at the top
    Given I am connected and viewing a channel
    And the help overlay is open
    When I press End
    Then the help overlay is scrolled down
    When I press Ctrl+H
    And I press Ctrl+H
    Then the help overlay is scrolled to the top
