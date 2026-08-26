@US-055
Feature: Voice only autoplays where you're actually looking

  As a user with more than one channel or DM active at once
  I want an incoming voice message to only play itself automatically in the
  channel/DM I currently have open
  So that voice from a conversation I'm not looking at doesn't play over
  whatever I'm actually doing, and I can still tell it arrived

  A voice message that never autoplayed - because it landed somewhere other
  than the one channel/DM on screen, exactly like one that was muted or
  still under identity review - shows a red "not listened" marker at the
  end of its line, until it is replayed manually.

  @AC-357
  Scenario: A voice message that arrives somewhere else shows a not listened marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into a channel I am not viewing
    When bob's voice message finishes after 2000 milliseconds
    Then the row shows a red not listened marker

  @AC-357
  Scenario: A voice message that autoplays in the channel I'm viewing shows no marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into the channel
    When bob's voice message finishes after 2000 milliseconds
    Then the row shows no not listened marker

  @AC-357
  Scenario: Replaying an unlistened voice message clears the marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into a channel I am not viewing
    And bob's voice message finishes after 2000 milliseconds
    Then the row shows a red not listened marker
    When I move focus to the messages
    And I press Enter
    Then the row shows no not listened marker

  @AC-357
  Scenario: A DM voice message that arrives while viewing a different surface shows a not listened marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into a private room I am not viewing
    When bob's private voice message finishes after 2000 milliseconds
    Then the private room shows a red not listened marker

  @AC-357
  Scenario: A DM voice message that autoplays in the private room I'm viewing shows no marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob starts streaming a voice message into our private room
    When bob's private voice message finishes after 2000 milliseconds
    Then the private room shows no not listened marker

  @AC-357
  Scenario: Replaying an unlistened DM voice message clears the marker
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into a private room I am not viewing
    And bob's private voice message finishes after 2000 milliseconds
    Then the private room shows a red not listened marker
    When I open a private room with bob
    And I move focus to the messages
    And I press Enter
    Then the private room shows no not listened marker
