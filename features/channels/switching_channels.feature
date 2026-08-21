@US-004
Feature: Moving between channels

  As a connected user
  I want to move between the channels I have joined and the rooms I have open
  So that I can land on the conversation I care about

  The top row holds two selectors - the channels I am a member of on the
  left, the DMs I have open on the right - each naming one entry at a time.
  Switching never joins anything: joining is `/channels` (the public
  directory) or Ctrl+J (by name). See docs/SPEC.md Functionality #2.

  @AC-020
  Scenario: The channel dropdown switches channel without joining anything
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    When I press the [ key
    Then the channel dropdown is open
    When I press Down
    Then the selected channel is "random"
    And no join is requested
    When I press Enter
    Then no dropdown is open
    And the selected channel is "random"

  @AC-020
  Scenario: Escape closes the dropdown, keeping what I moved onto
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    When I press the [ key
    And I press Up
    And I press Escape
    Then no dropdown is open
    And the selected channel is "random"

  @AC-020
  Scenario: The brackets move between the two selectors instead of wrapping
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I press the [ key
    Then no private room is open
    And no dropdown is open
    When I press the ] key
    Then the private room with bob is open
    And no dropdown is open

  @AC-020 @AC-186
  Scenario: The outward key on the DM selector opens its own dropdown
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have opened a private room with bob
    And I have opened a private room with carol
    When I press the ] key
    Then the DM dropdown is open
    When I press Down
    Then the private room with bob is open
    When I press the [ key
    Then no dropdown is open
    And the private room with bob is open

  @AC-020 @TB-026
  Scenario: Moving to the channel selector closes an open private room
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the channel already has joined "random"
    And I have opened a private room with bob
    When I press the [ key
    Then no private room is open

  @AC-185
  Scenario: The channel selector counts the channels it is not naming
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    Then the top row shows "+1 more..."
    And the top row does not show "random"

  @AC-186
  Scenario: The DM selector is not there until a room has been opened
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then the top row does not show "bob"
    When I open a private room with bob
    And I press the [ key
    Then the top row shows "bob"

  @AC-187
  Scenario: A message in a channel I am not looking at blinks an envelope
    Given I am connected and viewing a channel
    And the channel already has joined "random"
    When a message arrives in the channel "random"
    Then the top row's envelope blinks
    When I press the [ key
    And I press Down
    Then the top row shows no envelope

  @AC-189
  Scenario: Joining a channel lands me in it, ready to type
    Given I am connected and viewing a channel
    When the server confirms I joined "random"
    Then the selected channel is "random"
    And the top row shows "random"

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

  @AC-238
  Scenario: A dropdown longer than the screen scrolls instead of running off it
    Given I am connected and viewing a channel
    And the channel already has joined 30 more channels
    When I press the [ key
    Then the channel dropdown is open
    And the dropdown stops at the bottom of the screen and carries a scrollbar
    When I press Up
    Then the dropdown has scrolled to the far end of the list

  @AC-239
  Scenario: An unread DM blinks in the colour of the person it is from
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have opened a private room with carol
    And bob has sent me the private message "psst"
    When I press the [ key
    Then the DM selector's envelope is the same colour as the nickname beside it

  @AC-247
  Scenario: A channel can be typed the way it is shown
    Given I am connected and viewing a channel
    Then the channel selector names it with a leading hash
    When I press Ctrl+J
    And I type "#secret-room"
    And I press Enter
    Then joining the private channel "secret-room" is requested
